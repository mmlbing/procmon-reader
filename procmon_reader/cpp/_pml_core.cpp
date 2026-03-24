/*
 * _pml_core.cpp — pybind11 bindings for ProcmonReader.
 *
 * Exposes system_details, processes, filter_events,
 * read_events_batch, and event_count to Python.
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "procmon_reader.h"

namespace py = pybind11;


/* ================================================================
 * Parse Python filter tree → RawFilterNode
 *
 * Accepted formats:
 *   - [field, op, value]          → LEAF
 *   - {"AND": [child, ...]}        → AND
 *   - {"OR": [child, ...]}         → OR
 *   - {"NOT": child}               → NOT
 *   - None                         → empty (no filter)
 * ================================================================ */

static RawFilterNode parse_filter_tree(py::object obj) {
    if (obj.is_none())
        throw py::value_error("Unexpected None in filter tree node");

    /* Dict: AND / OR / NOT */
    if (py::isinstance<py::dict>(obj)) {
        auto d = obj.cast<py::dict>();
        if (d.size() != 1)
            throw py::value_error(
                "Filter dict must have exactly one key: 'AND', 'OR', or 'NOT'");

        for (auto &[key, value] : d) {
            std::string k = py::str(key).cast<std::string>();
            /* Uppercase */
            for (char &c : k)
                c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

            if (k == "AND" || k == "OR") {
                if (!py::isinstance<py::list>(value))
                    throw py::value_error(
                        "'" + k + "' value must be a list");
                auto lst = value.cast<py::list>();
                if (lst.size() < 2)
                    throw py::value_error(
                        "'" + k + "' requires at least 2 children");

                RawFilterNode node;
                node.type = (k == "AND") ? RawFilterNode::AND : RawFilterNode::OR;
                for (auto &item : lst)
                    node.children.push_back(parse_filter_tree(item.cast<py::object>()));
                return node;

            } else if (k == "NOT") {
                RawFilterNode node;
                node.type = RawFilterNode::NOT;
                node.children.push_back(parse_filter_tree(value.cast<py::object>()));
                return node;

            } else {
                throw py::value_error(
                    "Unknown filter key: '" + k + "'. Expected 'AND', 'OR', or 'NOT'");
            }
        }
    }

    /* List/tuple: [field, op, value] leaf */
    if (py::isinstance<py::list>(obj) || py::isinstance<py::tuple>(obj)) {
        auto seq = obj.cast<py::sequence>();
        if (seq.size() != 3)
            throw py::value_error(
                "Leaf rule must be [field, op, value] (3 elements), got " +
                std::to_string(seq.size()));

        RawFilterNode node;
        node.type = RawFilterNode::LEAF;
        node.field_name = seq[0].cast<std::string>();
        node.op = seq[1].cast<std::string>();

        /* Value: can be string, int, float, or bool */
        py::object val = seq[2].cast<py::object>();
        if (py::isinstance<py::bool_>(val)) {
            node.value_is_bool = true;
            node.value_bool = val.cast<bool>();
            node.value_str = node.value_bool ? "True" : "False";
        } else if (py::isinstance<py::int_>(val)) {
            node.value_is_num = true;
            node.value_num = val.cast<double>();
            node.value_str = std::to_string(val.cast<int64_t>());
        } else if (py::isinstance<py::float_>(val)) {
            node.value_is_num = true;
            node.value_num = val.cast<double>();
            node.value_str = std::to_string(node.value_num);
        } else {
            node.value_str = val.cast<std::string>();
        }

        return node;
    }

    throw py::value_error("Filter element must be a dict, list, or tuple");
}


/* ================================================================
 * PyProcmonReader — Python wrapper
 * ================================================================ */

class PyProcmonReader {
public:
    explicit PyProcmonReader(const std::string &file_path) {
        reader_ = std::make_unique<ProcmonReader>(file_path);
    }

    void close() {
        if (reader_) reader_->close();
    }

    /* --- system_details --- */
    py::dict system_details() const {
        auto details = reader_->system_details();
        py::dict result;
        for (auto &[k, v] : details)
            result[py::str(k)] = py::str(v);
        return result;
    }

    /* --- processes --- */
    py::list processes(int tz_offset_seconds) const {
        py::list result;
        const auto &table = reader_->process_table();

        /* Sort by process_index for stable output */
        std::vector<const PmlProcessInfo *> sorted;
        sorted.reserve(table.size());
        for (auto &[idx, pi] : table)
            sorted.push_back(&pi);
        std::sort(sorted.begin(), sorted.end(),
            [](const PmlProcessInfo *a, const PmlProcessInfo *b) {
                return a->process_index < b->process_index;
            });

        for (const auto *pi : sorted) {
            py::dict d;
            d["process_index"] = pi->process_index;
            d["pid"] = pi->process_id;
            d["parent_pid"] = pi->parent_process_id;
            d["parent_process_index"] = pi->parent_process_index;
            d["authentication_id"] = pi->authentication_id;
            d["session"] = pi->session_number;
            d["start_time"] = pml_fmt::format_timestamp(pi->start_time, tz_offset_seconds);
            d["end_time"] = pml_fmt::format_timestamp(pi->end_time, tz_offset_seconds);
            d["virtualized"] = pi->is_virtualized;
            d["is_64_bit"] = pi->is_64bit;
            d["integrity"] = pi->integrity;
            d["user"] = pi->user;
            d["process_name"] = pi->process_name;
            d["image_path"] = pi->image_path;
            d["command_line"] = pi->command_line;
            d["company"] = pi->company;
            d["version"] = pi->version;
            d["description"] = pi->description;

            result.append(d);
        }
        return result;
    }

    /* --- process_modules --- */
    py::list process_modules(uint32_t process_index) const {
        const auto &table = reader_->process_table();
        auto it = table.find(process_index);
        if (it == table.end())
            throw std::out_of_range(
                "process_index " + std::to_string(process_index) + " not found");
        const PmlProcessInfo *pi = &it->second;

        py::list mods;
        for (auto &mod : pi->modules) {
            py::dict md;
            md["base_address"] = mod.base_address;
            md["size"] = mod.size;
            md["path"] = mod.path;
            md["version"] = mod.version;
            md["company"] = mod.company;
            md["description"] = mod.description;
            md["timestamp"] = mod.timestamp;
            mods.append(md);
        }
        return mods;
    }

    /* --- Properties --- */
    uint32_t event_count() const { return reader_->event_count(); }

    /* --- filter_events (all_cpp.md API) ---
     * filter_tree: Python dict/list or None
     * tz_offset_seconds: timezone offset in seconds from UTC
     */
    py::list filter_events(py::object filter_tree, int tz_offset_seconds,
                           int num_threads = 0) const {
        std::unique_ptr<RawFilterNode> tree;
        if (!filter_tree.is_none()) {
            tree = std::make_unique<RawFilterNode>(parse_filter_tree(filter_tree));
        }

        std::vector<int64_t> matched;
        {
            py::gil_scoped_release release;
            matched = reader_->filter_events(
                tree.get(), tz_offset_seconds, num_threads);
        }

        py::list result;
        for (int64_t idx : matched)
            result.append(idx);
        return result;
    }

    /* --- read_events_batch (all_cpp.md API) ---
     * indices: list of event indices
     * select_fields: list of field name strings
     * tz_offset_seconds: timezone offset in seconds from UTC
     */
    py::list read_events_batch(py::list py_indices,
                               py::list py_select_fields,
                               int tz_offset_seconds) const {
        /* Convert indices */
        std::vector<int64_t> indices;
        indices.reserve(py_indices.size());
        for (auto &item : py_indices)
            indices.push_back(item.cast<int64_t>());

        /* Convert field names */
        std::vector<std::string> fields;
        fields.reserve(py_select_fields.size());
        for (auto &item : py_select_fields)
            fields.push_back(item.cast<std::string>());

        /* Call C++ implementation */
        std::vector<EventOutput> events = reader_->read_events_batch(
            indices, fields, tz_offset_seconds);

        /* Convert to Python dicts */
        py::module_ json_mod = py::module_::import("json");
        py::object json_loads = json_mod.attr("loads");

        py::list result;
        for (auto &event : events) {
            py::dict d;
            for (auto &[key, val] : event) {
                std::visit([&](auto &&v) {
                    using T = std::decay_t<decltype(v)>;
                    if constexpr (std::is_same_v<T, std::string>) {
                        if (key == "detail" && !v.empty() &&
                            v.front() == '{' && v.back() == '}') {
                            try {
                                d[py::str(key)] = json_loads(v);
                            } catch (...) {
                                d[py::str(key)] = py::str(v);
                            }
                        } else {
                            d[py::str(key)] = py::str(v);
                        }
                    } else if constexpr (std::is_same_v<T, int64_t>) {
                        d[py::str(key)] = v;
                    } else if constexpr (std::is_same_v<T, bool>) {
                        d[py::str(key)] = v;
                    } else if constexpr (std::is_same_v<T, std::vector<uint64_t>>) {
                        py::list lst;
                        for (uint64_t addr : v)
                            lst.append(addr);
                        d[py::str(key)] = lst;
                    }
                }, val);
            }
            result.append(d);
        }
        return result;
    }

private:
    std::unique_ptr<ProcmonReader> reader_;
};


/* ================================================================
 * Module definition (all_cpp.md: strict interface)
 * ================================================================ */

PYBIND11_MODULE(_pml_core, m) {
    m.doc() = "C++17 ProcmonReader — pybind11 binding.\n"
              "Provides PML file reading, filtering, and formatted event output.\n";

    py::class_<PyProcmonReader>(m, "ProcmonReaderCore")
        .def(py::init<const std::string &>(),
             py::arg("file_path"))
        .def("close", &PyProcmonReader::close)
        .def("system_details", &PyProcmonReader::system_details)
        .def("processes", &PyProcmonReader::processes,
             py::arg("tz_offset_seconds"))
        .def("process_modules", &PyProcmonReader::process_modules,
             py::arg("process_index"))
        .def_property_readonly("event_count", &PyProcmonReader::event_count)
        .def("filter_events", &PyProcmonReader::filter_events,
             py::arg("filter_tree"), py::arg("tz_offset_seconds"),
             py::arg("num_threads") = 0)
        .def("read_events_batch", &PyProcmonReader::read_events_batch,
             py::arg("indices"), py::arg("select_fields"),
             py::arg("tz_offset_seconds"));
}
