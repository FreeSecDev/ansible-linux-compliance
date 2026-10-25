(function () {
  "use strict";

  const SECTION_ORDER = [
    "compliance",
    "tests",
    "coverage",
    "lint",
    "vulnerabilities",
    "sbom",
    "molecule",
    "packer",
    "codebuild"
  ];
  const SECTION_TITLES = {
    compliance: "Compliance",
    tests: "Tests",
    coverage: "Coverage",
    lint: "Ansible lint",
    vulnerabilities: "Vulnerabilities",
    sbom: "SBOM",
    molecule: "Molecule",
    packer: "Packer images",
    codebuild: "AWS CodeBuild"
  };
  const SCOPE_TEXT = {
    single_host: "single host",
    multi_host: "multi-host",
    benchmark: "benchmark",
    fleet: "fleet"
  };
  const SECTION_STATUS_TEXT = {
    available: "available",
    partial: "partial: some inputs are missing",
    unavailable: "unavailable",
    error: "error: an input is invalid"
  };
  const RUN_STATUS_TEXT = {
    completed: "run completed",
    failed: "run failed",
    timed_out: "run timed out",
    not_completed: "not every run completed"
  };
  const ASSESSMENT_TEXT = {
    run_not_completed: "run not completed: no figure is given",
    nothing_evaluated: "nothing evaluated: no figure is given",
    all_evaluated_passed: "all evaluated rules passed",
    findings_open: "findings open"
  };
  const OUTCOME_ORDER = ["error", "fail", "notchecked", "waived", "pass", "notapplicable", "disabled"];
  const IN_DENOMINATOR = {
    pass: "yes",
    fail: "yes",
    waived: "yes, never counted as pass",
    notchecked: "yes, never counted as pass",
    error: "yes, never counted as pass",
    notapplicable: "no, shown separately",
    disabled: "no, shown separately"
  };
  const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];
  const TONES = {
    ok: [
      "available", "pass", "completed", "all_evaluated_passed", "passed", "SUCCEEDED",
      "applied", "already_compliant"
    ],
    bad: [
      "error", "fail", "failed", "timed_out", "not_completed", "run_not_completed", "FAILED", "FAULT",
      "TIMED_OUT", "critical", "high", "expired"
    ],
    warn: [
      "partial", "notchecked", "waived", "findings_open", "skipped", "STOPPED", "IN_PROGRESS", "medium",
      "self_asserted", "unnamed", "truncated", "active", "notselected", "informational"
    ],
    neutral: [
      "unavailable", "notapplicable", "disabled", "nothing_evaluated", "none", "low", "info", "unknown",
      "fixed"
    ]
  };
  const PAGE_SIZES = [25, 100, 500];
  const ATTRIBUTE = /^(?:aria-[a-z]+|role|id|class|type|tabindex|scope|colspan|for|lang|dir|value|autocomplete|spellcheck)$/;

  let counter = 0;
  const regionLabels = new Map();
  const toneOf = new Map();
  Object.keys(TONES).forEach(function (tone) {
    TONES[tone].forEach(function (value) {
      toneOf.set(value, tone);
    });
  });

  function regionLabel(caption) {
    const seen = (regionLabels.get(caption) || 0) + 1;
    regionLabels.set(caption, seen);
    return seen === 1 ? caption : caption + " (" + seen + ")";
  }

  function nextId(prefix) {
    counter += 1;
    return prefix + "-" + counter;
  }

  function append(node, children) {
    if (children === null || children === undefined || children === false) {
      return;
    }
    if (Array.isArray(children)) {
      children.forEach(function (child) {
        append(node, child);
      });
      return;
    }
    if (children instanceof Node) {
      node.appendChild(children);
      return;
    }
    node.appendChild(document.createTextNode(String(children)));
  }

  function el(tag, attributes, children) {
    const node = document.createElement(tag);
    if (attributes) {
      Object.keys(attributes).forEach(function (name) {
        const value = attributes[name];
        if (value === null || value === undefined || value === false) {
          return;
        }
        if (!ATTRIBUTE.test(name)) {
          throw new Error("attribute is not allowed");
        }
        node.setAttribute(name, value === true ? "" : String(value));
      });
    }
    append(node, children);
    return node;
  }

  function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function obj(value) {
    return isObject(value) ? value : {};
  }

  function list(value) {
    return Array.isArray(value) ? value : [];
  }

  function present(value) {
    return value !== null && value !== undefined;
  }

  function plain(value) {
    if (!present(value)) {
      return "";
    }
    if (typeof value === "number") {
      return number(value);
    }
    return String(value);
  }

  function number(value) {
    if (typeof value !== "number") {
      return plain(value);
    }
    return String(value);
  }

  function decimal(value) {
    if (typeof value !== "number") {
      return plain(value);
    }
    return Number.isInteger(value) ? value.toFixed(1) : String(value);
  }

  function missing(text) {
    return el("span", { class: "missing" }, text || "none");
  }

  function val(value, missingText) {
    if (!present(value) || value === "") {
      return missing(missingText);
    }
    return el("bdi", { class: "v" }, plain(value));
  }

  function mono(value, missingText) {
    if (!present(value) || value === "") {
      return missing(missingText);
    }
    return el("bdi", { class: "v mono" }, plain(value));
  }

  function badge(value, label) {
    const tone = toneOf.get(value) || "neutral";
    return el("span", { class: "badge tone-" + tone }, label || el("bdi", { class: "v" }, plain(value)));
  }

  function yesNo(flag, yes, no) {
    return flag ? badge("truncated", yes) : el("span", null, no);
  }

  function pairs(entries) {
    const dl = el("dl", { class: "pairs" });
    entries.forEach(function (entry) {
      dl.appendChild(el("dt", null, entry[0]));
      dl.appendChild(el("dd", null, entry[1]));
    });
    return dl;
  }

  function callout(tone, title, body) {
    return el("div", { class: "callout tone-" + tone, role: "note" }, [
      el("p", { class: "callout-title" }, title),
      body
    ]);
  }

  function simpleTable(caption, headers, rows) {
    const table = el("table", null, [
      el("caption", null, caption),
      el("thead", null, el("tr", null, headers.map(function (header) {
        return el("th", { scope: "col" }, header);
      }))),
      el("tbody", null, rows.map(function (row) {
        return el("tr", null, row.map(function (cell) {
          return el("td", null, cell);
        }));
      }))
    ]);
    return el("div", { class: "table-wrap", role: "region", "aria-label": regionLabel(caption), tabindex: "0" }, table);
  }

  function compareKeys(left, right) {
    const leftMissing = !present(left) || left === "";
    const rightMissing = !present(right) || right === "";
    if (leftMissing || rightMissing) {
      return leftMissing === rightMissing ? 0 : leftMissing ? 1 : -1;
    }
    if (typeof left === "number" && typeof right === "number") {
      return left - right;
    }
    const a = String(left);
    const b = String(right);
    return a < b ? -1 : a > b ? 1 : 0;
  }

  function rankIn(order) {
    return function (value) {
      const index = order.indexOf(value);
      return index < 0 ? order.length : index;
    };
  }

  function dataTable(config) {
    const id = nextId("table");
    const columns = config.columns;
    const rows = config.rows;
    const state = { sort: -1, direction: "none", page: 0, size: PAGE_SIZES[0], query: "", filters: {} };
    const expanded = new Set();
    const haystacks = new Array(rows.length);
    let view = rows.map(function (_row, index) {
      return index;
    });
    let timer = null;

    const root = el("div", { class: "data-table" });
    const controls = el("div", { class: "controls" });
    const search = el("input", {
      type: "search",
      id: id + "-search",
      autocomplete: "off",
      spellcheck: "false"
    });
    controls.appendChild(el("label", { for: id + "-search" }, ["Search " + config.caption, search]));
    columns.forEach(function (column, index) {
      if (!column.filter) {
        return;
      }
      const selectId = id + "-filter-" + index;
      const select = el("select", { id: selectId }, el("option", { value: "" }, "All"));
      const seen = new Map();
      rows.forEach(function (row) {
        const key = plain(column.filterValue ? column.filterValue(row) : column.value(row));
        if (!seen.has(key)) {
          seen.set(key, column.filterLabel ? column.filterLabel(row) : key || "(none)");
        }
      });
      Array.from(seen.keys()).sort(function (a, b) {
        return column.rank ? column.rank(a) - column.rank(b) || compareKeys(a, b) : compareKeys(a, b);
      }).forEach(function (key) {
        select.appendChild(el("option", { value: key }, seen.get(key)));
      });
      select.addEventListener("change", function () {
        state.filters[index] = select.value;
        state.page = 0;
        refresh();
      });
      controls.appendChild(el("label", { for: selectId }, [column.label, select]));
    });
    const sizeId = id + "-size";
    const size = el("select", { id: sizeId }, PAGE_SIZES.map(function (value) {
      return el("option", { value: String(value) }, String(value));
    }));
    size.addEventListener("change", function () {
      state.size = Number(size.value);
      state.page = 0;
      draw();
    });
    controls.appendChild(el("label", { for: sizeId }, ["Rows per page", size]));
    root.appendChild(controls);

    const status = el("p", { class: "table-status", role: "status", "aria-live": "polite" });
    root.appendChild(status);

    const headerRow = el("tr");
    const headers = [];
    if (config.detail) {
      headerRow.appendChild(el("th", { scope: "col" }, el("span", { class: "sr-only" }, "Details")));
    }
    columns.forEach(function (column, index) {
      if (column.sortable === false) {
        headers.push(null);
        headerRow.appendChild(el("th", { scope: "col" }, column.label));
        return;
      }
      const mark = el("span", { class: "sort-mark", "aria-hidden": "true" }, "");
      const button = el("button", { type: "button", class: "sort" }, [column.label, " ", mark]);
      const th = el("th", { scope: "col", "aria-sort": "none" }, button);
      button.addEventListener("click", function () {
        sortBy(index);
      });
      headers.push({ th: th, mark: mark });
      headerRow.appendChild(th);
    });
    const tbody = el("tbody");
    const table = el("table", { id: id }, [el("caption", null, config.caption), el("thead", null, headerRow), tbody]);
    root.appendChild(el("div", {
      class: "table-wrap",
      role: "region",
      "aria-label": regionLabel(config.caption),
      tabindex: "0"
    }, table));

    const first = el("button", { type: "button" }, "First page");
    const previous = el("button", { type: "button" }, "Previous page");
    const pageText = el("span");
    const next = el("button", { type: "button" }, "Next page");
    const last = el("button", { type: "button" }, "Last page");
    const pager = el("div", { class: "pager", role: "group", "aria-label": "Pages of " + config.caption }, [
      first, previous, pageText, next, last
    ]);
    root.appendChild(pager);
    first.addEventListener("click", function () {
      goTo(0);
    });
    previous.addEventListener("click", function () {
      goTo(state.page - 1);
    });
    next.addEventListener("click", function () {
      goTo(state.page + 1);
    });
    last.addEventListener("click", function () {
      goTo(pageCount() - 1);
    });

    search.addEventListener("input", function () {
      if (timer !== null) {
        clearTimeout(timer);
      }
      timer = setTimeout(function () {
        timer = null;
        state.query = search.value.trim().toLowerCase();
        state.page = 0;
        refresh();
      }, 200);
    });

    function haystack(index) {
      if (haystacks[index] === undefined) {
        const row = rows[index];
        haystacks[index] = columns.map(function (column) {
          return plain(column.search ? column.search(row) : column.value(row));
        }).join("\u0000").toLowerCase();
      }
      return haystacks[index];
    }

    function pageCount() {
      return Math.max(1, Math.ceil(view.length / state.size));
    }

    function goTo(page) {
      state.page = Math.min(Math.max(0, page), pageCount() - 1);
      draw();
    }

    function sortBy(index) {
      if (state.sort === index) {
        state.direction = state.direction === "ascending" ? "descending" : "ascending";
      } else {
        state.sort = index;
        state.direction = "ascending";
      }
      headers.forEach(function (header, position) {
        if (header === null) {
          return;
        }
        const active = position === state.sort;
        header.th.setAttribute("aria-sort", active ? state.direction : "none");
        header.mark.textContent = active ? (state.direction === "ascending" ? "\u25b2" : "\u25bc") : "";
      });
      refresh();
    }

    function refresh() {
      const filters = Object.keys(state.filters).filter(function (key) {
        return state.filters[key] !== "";
      });
      view = [];
      for (let index = 0; index < rows.length; index += 1) {
        const row = rows[index];
        let keep = filters.every(function (key) {
          const column = columns[Number(key)];
          return plain(column.filterValue ? column.filterValue(row) : column.value(row)) === state.filters[key];
        });
        if (keep && state.query !== "") {
          keep = haystack(index).indexOf(state.query) >= 0;
        }
        if (keep) {
          view.push(index);
        }
      }
      if (state.sort >= 0) {
        const column = columns[state.sort];
        const key = column.rank
          ? function (row) {
            return column.rank(column.value(row));
          }
          : column.sortValue || column.value;
        const keys = new Map();
        view.forEach(function (index) {
          keys.set(index, key(rows[index]));
        });
        const sign = state.direction === "descending" ? -1 : 1;
        view.sort(function (a, b) {
          return sign * compareKeys(keys.get(a), keys.get(b)) || a - b;
        });
      }
      state.page = Math.min(state.page, pageCount() - 1);
      draw();
    }

    function draw() {
      const start = state.page * state.size;
      const end = Math.min(view.length, start + state.size);
      const fragment = document.createDocumentFragment();
      const width = columns.length + (config.detail ? 1 : 0);
      for (let position = start; position < end; position += 1) {
        const index = view[position];
        const row = rows[index];
        const tr = el("tr");
        if (config.detail) {
          const detailId = id + "-detail-" + index;
          const open = expanded.has(index);
          const toggle = el("button", {
            type: "button",
            class: "details-toggle",
            "aria-expanded": open ? "true" : "false",
            "aria-controls": detailId
          }, [open ? "Hide details" : "Show details", el("span", { class: "sr-only" }, " of row " + (position + 1))]);
          toggle.addEventListener("click", function () {
            if (expanded.has(index)) {
              expanded.delete(index);
            } else {
              expanded.add(index);
            }
            draw();
            const again = document.querySelector("[aria-controls=\"" + detailId + "\"]");
            if (again) {
              again.focus();
            }
          });
          tr.appendChild(el("td", null, toggle));
        }
        columns.forEach(function (column) {
          tr.appendChild(el("td", null, column.cell ? column.cell(row) : val(column.value(row))));
        });
        fragment.appendChild(tr);
        if (config.detail && expanded.has(index)) {
          fragment.appendChild(el("tr", { class: "detail-row", id: id + "-detail-" + index }, el("td", {
            colspan: String(width)
          }, config.detail(row))));
        }
      }
      tbody.replaceChildren(fragment);
      if (view.length === 0) {
        tbody.appendChild(el("tr", null, el("td", { colspan: String(width) }, rows.length === 0
          ? (config.empty || "The report lists no entries here.")
          : "No rows match the search and filters.")));
      }
      status.textContent = view.length === 0
        ? "No rows shown."
        : "Rows " + (start + 1) + " to " + end + " of " + view.length + " matching rows in this table.";
      pageText.textContent = "Page " + (state.page + 1) + " of " + pageCount();
      first.disabled = state.page === 0;
      previous.disabled = state.page === 0;
      next.disabled = state.page >= pageCount() - 1;
      last.disabled = state.page >= pageCount() - 1;
    }

    refresh();
    return root;
  }

  function sourceOf(row) {
    return obj(obj(row.item).artifact).path;
  }

  function inputColumn() {
    return { label: "Input", value: sourceOf, cell: function (row) {
      return mono(sourceOf(row));
    }, filter: true };
  }

  function flatten(items, pick) {
    const rows = [];
    list(items).forEach(function (item) {
      const data = obj(obj(item).data);
      list(pick(data)).forEach(function (entry) {
        rows.push({ item: item, entry: obj(entry) });
      });
    });
    return rows;
  }

  function entryColumn(label, key, options) {
    const extra = options || {};
    return {
      label: label,
      value: function (row) {
        return row.entry[key];
      },
      cell: extra.cell ? function (row) {
        return extra.cell(row.entry[key], row);
      } : undefined,
      filter: extra.filter,
      rank: extra.rank,
      sortable: extra.sortable
    };
  }

  function badgeCell(value) {
    return present(value) ? badge(value) : missing();
  }

  const DATA = (function () {
    try {
      const node = document.getElementById("report-data");
      return obj(JSON.parse(node ? node.textContent : "null"));
    } catch (error) {
      return {};
    }
  })();
  const REPORT = obj(DATA.report);
  const VIEWS = obj(DATA.views);
  const SECTIONS = obj(REPORT.sections);
  const SCOPE = plain(REPORT.scope);
  const HOSTS = new Map();
  list(VIEWS.hosts).forEach(function (host) {
    HOSTS.set(hostKey(host), obj(host));
  });

  function hostKey(host) {
    const fields = obj(host);
    return JSON.stringify([fields.hostname || "", fields.machine_id || "", fields.input_sha256 || ""]);
  }

  function scopeLabel() {
    return SCOPE_TEXT[SCOPE] || SCOPE;
  }

  function hostLabel(host) {
    const fields = obj(host);
    const info = HOSTS.get(hostKey(fields)) || {};
    const name = fields.hostname ? fields.hostname : "unnamed input";
    let identity = "self-asserted";
    if (fields.machine_id) {
      identity = "machine ID " + fields.machine_id;
    } else if (!fields.hostname) {
      identity = "self-asserted, input " + plain(fields.input_sha256);
    }
    const variant = info.variants > 1 ? ", variant " + info.variant + " of " + info.variants : "";
    return name + " (" + identity + variant + ")";
  }

  function identityBadge(host) {
    const fields = obj(host);
    if (fields.machine_id) {
      return el("span", null, [badge("machine_id", "machine ID reported by the scan run"), " ", mono(fields.machine_id)]);
    }
    if (!fields.hostname) {
      return el("span", null, [
        badge("unnamed", "self-asserted: the input names no host"),
        " input ",
        mono(fields.input_sha256)
      ]);
    }
    return badge("self_asserted", "self-asserted (no machine ID)");
  }

  function hostCell(host, withIdentity) {
    const fields = obj(host);
    const info = HOSTS.get(hostKey(fields)) || {};
    const parts = [fields.hostname ? val(fields.hostname) : missing("unnamed input")];
    if (withIdentity !== false) {
      parts.push(" ");
      parts.push(identityBadge(fields));
    }
    if (info.variants > 1) {
      parts.push(" ");
      parts.push(el("span", { class: "badge tone-warn variant" },
        "same name as another host: variant " + info.variant + " of " + info.variants));
    }
    return el("span", null, parts);
  }

  function sectionTitle(name) {
    return SECTION_TITLES[name] || name;
  }

  function statusLine(section) {
    const status = plain(section.status);
    return el("p", null, ["Section status: ", badge(status, SECTION_STATUS_TEXT[status] || status)]);
  }

  function gapsTable(section) {
    const gaps = list(section.gaps);
    if (gaps.length === 0) {
      return null;
    }
    return simpleTable("Missing or invalid inputs", ["Input", "Status", "Reason"], gaps.map(function (gap) {
      const fields = obj(gap);
      return [mono(fields.artifact), badgeCell(fields.status), val(fields.reason)];
    }));
  }

  function sectionHeader(name, section) {
    const parts = [el("h2", null, sectionTitle(name)), statusLine(section)];
    const status = plain(section.status);
    if (status !== "available") {
      parts.push(callout(status === "error" ? "bad" : status === "partial" ? "warn" : "neutral",
        "This section has no summary because it is " + (SECTION_STATUS_TEXT[status] || status) + ".",
        [el("p", null, ["Reason: ", val(section.reason)]),
          el("p", null, "Entries from the inputs that did parse are still listed below; nothing here is a pass.")]));
    }
    parts.push(gapsTable(section));
    return parts;
  }

  function itemsTable(name, section, extraColumns) {
    const rows = list(section.items).map(function (item) {
      return { item: obj(item), entry: obj(obj(item).data) };
    });
    const columns = [
      { label: "Input", value: function (row) {
        return obj(row.item.artifact).path;
      }, cell: function (row) {
        return mono(obj(row.item.artifact).path);
      } },
      { label: "Format", value: function (row) {
        return row.item.format;
      }, filter: true },
      { label: "Status", value: function (row) {
        return row.item.status;
      }, cell: function (row) {
        return badgeCell(row.item.status);
      }, filter: true },
      { label: "Reason", value: function (row) {
        return row.item.reason;
      }, cell: function (row) {
        return val(row.item.reason, "none");
      } },
      { label: "SHA-256", value: function (row) {
        return obj(row.item.artifact).sha256;
      }, cell: function (row) {
        return mono(obj(row.item.artifact).sha256, "not read");
      } },
      { label: "Size in bytes", value: function (row) {
        return obj(row.item.artifact).size;
      }, cell: function (row) {
        return val(obj(row.item.artifact).size, "not read");
      } }
    ].concat(extraColumns || []);
    return [el("h3", null, "Inputs"), dataTable({ caption: sectionTitle(name) + " inputs", columns: columns, rows: rows })];
  }

  function truncationNotes(section) {
    const truncated = list(section.items).filter(function (item) {
      return obj(obj(item).data).truncated === true;
    });
    if (truncated.length === 0) {
      return null;
    }
    return callout("warn", "Some detail lists are truncated by the report.", el("ul", { class: "plain" },
      truncated.map(function (item) {
        return el("li", null, ["Only the first entries of ", mono(obj(obj(item).artifact).path),
          " are listed; the totals in the report are complete."]);
      })));
  }

  function countsTable(caption, counts, order) {
    const fields = obj(counts);
    const keys = order ? order.filter(function (key) {
      return key in fields;
    }).concat(Object.keys(fields).filter(function (key) {
      return order.indexOf(key) < 0;
    }).sort()) : Object.keys(fields).sort();
    return simpleTable(caption, ["Name", "Count"], keys.map(function (key) {
      return [badge(key), val(fields[key])];
    }));
  }

  function summaryPairs(summary, keys) {
    const fields = obj(summary);
    return pairs(keys.map(function (key) {
      return [key[1], val(fields[key[0]])];
    }));
  }

  function percentLine(summary) {
    const fields = obj(summary);
    const counts = obj(fields.counts);
    if (typeof fields.compliance_percent === "number") {
      return el("p", { class: "headline" }, [
        "Pass percentage: ", el("bdi", { class: "v" }, decimal(fields.compliance_percent) + " %"),
        " (", val(counts.pass), " pass of ", val(fields.evaluated), " evaluated, scope ", scopeLabel(), ")"
      ]);
    }
    return el("p", { class: "headline" }, [
      "No pass percentage: ",
      ASSESSMENT_TEXT[fields.assessment] || "the report gives none",
      " (", val(fields.evaluated), " evaluated, scope ", scopeLabel(), ")"
    ]);
  }

  function complianceSummary(summary, caption) {
    const fields = obj(summary);
    const counts = obj(fields.counts);
    return el("div", { class: "figure" }, [
      el("p", null, [
        badge(fields.run_status, RUN_STATUS_TEXT[fields.run_status] || plain(fields.run_status)),
        " ",
        badge(fields.assessment, ASSESSMENT_TEXT[fields.assessment] || plain(fields.assessment))
      ]),
      percentLine(fields),
      pairs([
        ["Runs summarised", val(fields.runs_total)],
        ["Runs not completed", val(fields.runs_not_completed)],
        ["Evaluated (denominator)", val(fields.evaluated)],
        ["Not selected by the profile", [val(fields.not_selected), " (informational, never in the figures)"]],
        ["Expired waivers", [val(fields.expired_waivers), " (counted as their evaluated outcome)"]]
      ]),
      simpleTable(caption + ": rules per outcome", ["Outcome", "Rules", "In the denominator"],
        OUTCOME_ORDER.map(function (outcome) {
          return [badge(outcome), val(counts[outcome]), IN_DENOMINATOR[outcome]];
        })),
      countsTable(caption + ": open rules (fail, error, notchecked) per severity", fields.open_by_severity,
        SEVERITY_ORDER)
    ]);
  }

  function shaList(sources) {
    return el("ul", { class: "plain" }, list(sources).map(function (source) {
      return el("li", null, mono(source));
    }));
  }

  function noteText(note) {
    const fields = obj(note);
    if (fields.kind === "shared_self_asserted_host") {
      return [
        "Several inputs claim the self-asserted host name ", val(fields.host),
        " and are counted as one host. Figures stay separate for each benchmark and content version; "
          + "a host group shows a merge only when it combines inputs itself. Inputs: ",
        shaList(fields.sources)
      ];
    }
    return ["Note of kind ", val(fields.kind), " for host ", val(fields.host)];
  }

  function mergeText(merge) {
    const note = obj(list(obj(SECTIONS.compliance).notes)[obj(merge).note]);
    return [
      "Merged in this group: these inputs claim the self-asserted host name ", val(note.host),
      " and are combined into this group: ",
      shaList(obj(merge).sources)
    ];
  }

  function groupSources(index) {
    return list(obj(list(VIEWS.groups)[index]).sources);
  }

  function groupMerges(index) {
    return list(obj(list(VIEWS.groups)[index]).merges);
  }

  function sourceList(sources) {
    if (sources.length === 0) {
      return missing("no input listed");
    }
    return el("ul", { class: "plain" }, sources.map(function (source) {
      const fields = obj(source);
      return el("li", null, [badge(fields.format), " ", mono(fields.sha256), " ", mono(fields.path)]);
    }));
  }

  function figureCell(summary) {
    const fields = obj(summary);
    if (typeof fields.compliance_percent === "number") {
      return el("span", null, [
        el("bdi", { class: "v" }, decimal(fields.compliance_percent) + " %"),
        " (", val(obj(fields.counts).pass), " of ", val(fields.evaluated), ")"
      ]);
    }
    return missing("no figure");
  }

  function compliancePanel() {
    const section = obj(SECTIONS.compliance);
    const parts = sectionHeader("compliance", section);
    parts.push(el("p", null, "Rule results are scan evidence. They are not a statement of compliance with "
      + "ISO 27001, PCI DSS, NIST, NIS2 or any other framework."));
    if (isObject(section.summary)) {
      parts.push(el("h3", null, "Summary"));
      parts.push(el("p", null, "One benchmark and content version, pooled over the " + scopeLabel() + " scope."));
      parts.push(complianceSummary(section.summary, "Summary"));
    } else if (section.status === "available") {
      parts.push(callout("neutral", "No single summary.",
        el("p", null, "The report covers several benchmarks or content versions, which are never pooled. "
          + "See the figures per benchmark and per host below.")));
    }
    const notes = list(section.notes);
    if (notes.length > 0) {
      parts.push(el("h3", null, "Hosts counted as one"));
      parts.push(el("ul", null, notes.map(function (note) {
        return el("li", null, noteText(note));
      })));
    }
    parts.push(el("h3", null, "Figures per benchmark and content version"));
    if (SCOPE === "single_host") {
      parts.push(el("p", null, "Not produced for the single host scope; see the per-host figures."));
    } else {
      parts.push(dataTable({
        caption: "Pooled figures (scope " + scopeLabel() + ")",
        rows: list(section.aggregates).map(obj),
        detail: function (row) {
          return complianceSummary(row.summary, "Pooled figure");
        },
        columns: [
          { label: "Benchmark", value: function (row) {
            return row.benchmark_id;
          }, filter: true },
          { label: "Content version", value: function (row) {
            return row.content_version;
          } },
          { label: "Scope", value: function (row) {
            return SCOPE_TEXT[row.scope] || row.scope;
          } },
          { label: "Hosts", value: function (row) {
            return row.host_count;
          } },
          { label: "Run status", value: function (row) {
            return obj(row.summary).run_status;
          }, cell: function (row) {
            return badgeCell(obj(row.summary).run_status);
          }, filter: true },
          { label: "Assessment", value: function (row) {
            return obj(row.summary).assessment;
          }, cell: function (row) {
            return badge(obj(row.summary).assessment, ASSESSMENT_TEXT[obj(row.summary).assessment]);
          }, filter: true },
          { label: "Pass percentage", value: function (row) {
            return obj(row.summary).compliance_percent;
          }, cell: function (row) {
            return figureCell(row.summary);
          } }
        ]
      }));
    }
    parts.push(el("h3", null, "Figures per host"));
    parts.push(el("p", null, "Each row is one benchmark and content version on one host. A host is identified "
      + "by its machine ID when a scan run supplies one; otherwise its name is self-asserted by the input file."));
    parts.push(dataTable({
      caption: "Host groups",
      rows: list(section.groups).map(function (group, index) {
        return { group: obj(group), index: index };
      }),
      detail: function (row) {
        return complianceSummary(row.group.summary, "Host group");
      },
      columns: [
        { label: "Host", value: function (row) {
          return hostLabel(row.group.host);
        }, cell: function (row) {
          return hostCell(row.group.host, false);
        } },
        { label: "Identity", value: function (row) {
          return obj(HOSTS.get(hostKey(row.group.host))).identity;
        }, cell: function (row) {
          return identityBadge(row.group.host);
        }, filter: true },
        { label: "Benchmark", value: function (row) {
          return row.group.benchmark_id;
        }, filter: true },
        { label: "Content version", value: function (row) {
          return row.group.content_version;
        } },
        { label: "Run status", value: function (row) {
          return obj(row.group.summary).run_status;
        }, cell: function (row) {
          return badge(obj(row.group.summary).run_status, RUN_STATUS_TEXT[obj(row.group.summary).run_status]);
        }, filter: true },
        { label: "Assessment", value: function (row) {
          return obj(row.group.summary).assessment;
        }, cell: function (row) {
          return badge(obj(row.group.summary).assessment, ASSESSMENT_TEXT[obj(row.group.summary).assessment]);
        }, filter: true },
        { label: "Pass percentage", value: function (row) {
          return obj(row.group.summary).compliance_percent;
        }, cell: function (row) {
          return figureCell(row.group.summary);
        } },
        { label: "Input sources", sortable: false, value: function (row) {
          return groupSources(row.index).map(function (source) {
            return [obj(source).format, obj(source).sha256, obj(source).path].join(" ");
          }).join(" ");
        }, cell: function (row) {
          return sourceList(groupSources(row.index));
        } },
        { label: "Merge notes", sortable: false, value: function (row) {
          return groupMerges(row.index).length > 0 ? "merged" : "";
        }, cell: function (row) {
          const merges = groupMerges(row.index);
          if (merges.length === 0) {
            return missing("none");
          }
          return el("ul", { class: "plain" }, merges.map(function (merge) {
            return el("li", null, mergeText(merge));
          }));
        } }
      ]
    }));
    parts.push(el("h3", null, "Rules"));
    parts.push(el("p", null, "One row per rule, host and content version. When several scans evaluated a rule, "
      + "the worst outcome is shown and every source keeps its own outcome."));
    parts.push(dataTable({
      caption: "Rules",
      rows: list(section.rules).map(obj),
      detail: function (row) {
        return simpleTable("Sources of " + plain(row.rule_id), ["Input", "Benchmark", "Profile", "Outcome", "Expired waiver"],
          list(row.sources).map(function (source) {
            const fields = obj(source);
            return [mono(fields.artifact), val(fields.benchmark_id), val(fields.profile_id), badgeCell(fields.outcome),
              fields.expired_waiver ? badge("expired", "waiver expired") : "no"];
          }));
      },
      columns: [
        { label: "Rule ID", value: function (row) {
          return row.rule_id;
        }, cell: function (row) {
          return mono(row.rule_id);
        } },
        { label: "Host", value: function (row) {
          return hostLabel(row.host);
        }, filterValue: function (row) {
          return hostKey(row.host);
        }, filterLabel: function (row) {
          return hostLabel(row.host);
        }, cell: function (row) {
          return hostCell(row.host);
        }, filter: true },
        { label: "Content version", value: function (row) {
          return row.content_version;
        }, filter: true },
        { label: "Outcome", value: function (row) {
          return row.outcome;
        }, cell: function (row) {
          return badgeCell(row.outcome);
        }, filter: true, rank: rankIn(OUTCOME_ORDER) },
        { label: "Severity", value: function (row) {
          return row.severity;
        }, cell: function (row) {
          return badgeCell(row.severity);
        }, filter: true, rank: rankIn(SEVERITY_ORDER) },
        { label: "Waiver", value: function (row) {
          return row.expired_waiver ? "expired" : "";
        }, cell: function (row) {
          return row.expired_waiver ? badge("expired", "waiver expired") : missing("no expired waiver");
        }, filter: true }
      ]
    }));
    parts.push(itemsTable("compliance", section, [
      { label: "Kind", value: function (row) {
        return row.entry.kind;
      } },
      { label: "Scan status", value: function (row) {
        return row.entry.scan_status;
      }, cell: function (row) {
        return present(row.entry.scan_status)
          ? badge(row.entry.scan_status, RUN_STATUS_TEXT[row.entry.scan_status]) : missing("not parsed");
      }, filter: true },
      { label: "Host", value: function (row) {
        const host = obj(row.entry.host);
        return host.hostname || row.entry.reported_host;
      }, cell: function (row) {
        const host = obj(row.entry.host);
        if (host.hostname) {
          return el("span", null, [val(host.hostname), " ", host.machine_id
            ? el("span", null, [badge("machine_id", "machine ID reported by the scan run"), " ", mono(host.machine_id)])
            : badge("self_asserted", "self-asserted (no machine ID)")]);
        }
        if (present(row.entry.reported_host)) {
          return el("span", null, [val(row.entry.reported_host), " ", badge("self_asserted", "self-asserted by the file")]);
        }
        return present(row.entry.kind) ? badge("unnamed", "the input names no host") : missing("not parsed");
      } },
      { label: "Benchmark", value: function (row) {
        return row.entry.benchmark_id;
      } },
      { label: "Per-input figure", value: function (row) {
        return obj(row.entry.summary).compliance_percent;
      }, cell: function (row) {
        return isObject(row.entry.summary) ? figureCell(row.entry.summary) : missing("not parsed");
      } }
    ]));
    parts.push(el("h3", null, "Findings by input"));
    parts.push(findingsTable(section));
    return parts;
  }

  function findingsTable(section) {
    const rows = [];
    list(section.items).forEach(function (item) {
      const data = obj(obj(item).data);
      const findings = isObject(data.scan_run) ? obj(data.scan_run).findings : data.findings;
      list(findings).forEach(function (finding) {
        rows.push({ item: item, entry: obj(finding), data: data });
      });
    });
    return dataTable({
      caption: "Findings",
      rows: rows,
      detail: function (row) {
        const finding = row.entry;
        const exception = obj(finding.exception);
        const remediation = obj(finding.remediation);
        return [
          pairs([
            ["Message", val(finding.message)],
            ["Evaluated outcome", badgeCell(finding.evaluated_outcome)],
            ["Exception", [badgeCell(exception.state), " ", val(exception.exception_id, "no ID")]],
            ["Exception reason", val(exception.reason)],
            ["Exception expires", val(exception.expires_at)],
            ["Disabled by", mono(finding.disabled_by)],
            ["Remediation", isObject(finding.remediation)
              ? [badgeCell(remediation.status), " changed: ", remediation.changed ? "yes" : "no", " ", val(remediation.message)]
              : missing()],
            ["Run", [badgeCell(row.data.scan_status), " ", val(row.data.error_message, "no error message")]]
          ]),
          list(finding.evidence).length === 0 ? el("p", null, missing("no evidence")) : el("div", null,
            list(finding.evidence).map(function (evidence) {
              const fields = obj(evidence);
              return el("div", null, [
                el("h4", null, ["Evidence ", val(fields.kind), " from ", val(fields.source)]),
                el("pre", { class: "v" }, plain(fields.content))
              ]);
            }))
        ];
      },
      columns: [
        inputColumn(),
        entryColumn("Rule ID", "rule_id", { cell: function (value) {
          return mono(value);
        } }),
        entryColumn("Outcome", "outcome", { cell: badgeCell, filter: true, rank: rankIn(OUTCOME_ORDER) }),
        entryColumn("Severity", "severity", { cell: badgeCell, filter: true, rank: rankIn(SEVERITY_ORDER) }),
        { label: "Flags", value: function (row) {
          return list(row.entry.flags).join(" ");
        }, cell: function (row) {
          const flags = list(row.entry.flags);
          return flags.length === 0 ? missing() : el("span", null, flags.map(function (flag) {
            return badge(flag);
          }));
        }, filter: true },
        { label: "Exception", value: function (row) {
          return obj(row.entry.exception).state;
        }, cell: function (row) {
          const state = obj(row.entry.exception).state;
          return state === "none" ? missing("none") : badge(state, state === "active" ? "waiver active" : "waiver " + plain(state));
        }, filter: true },
        { label: "Disabled by", value: function (row) {
          return row.entry.disabled_by;
        }, cell: function (row) {
          return mono(row.entry.disabled_by);
        } }
      ]
    });
  }

  function genericPanel(name, extraItems, details) {
    const section = obj(SECTIONS[name]);
    const parts = sectionHeader(name, section);
    if (isObject(section.summary)) {
      parts.push(el("h3", null, "Summary"));
      const summary = section.summary;
      const counts = Object.keys(summary).filter(function (key) {
        return !isObject(summary[key]);
      }).sort().map(function (key) {
        return [key.replace(/_/g, " "), val(summary[key])];
      });
      parts.push(pairs(counts));
      if (isObject(summary.by_severity)) {
        parts.push(countsTable("Summary per severity", summary.by_severity, SEVERITY_ORDER));
      }
    }
    parts.push(truncationNotes(section));
    parts.push(itemsTable(name, section, extraItems));
    (details || []).forEach(function (detail) {
      parts.push(el("h3", null, detail.title));
      parts.push(dataTable({ caption: detail.title, rows: flatten(section.items, detail.pick), columns: [inputColumn()].concat(detail.columns) }));
    });
    return parts;
  }

  function dataColumn(label, key, options) {
    const extra = options || {};
    return {
      label: label,
      value: function (row) {
        return row.entry[key];
      },
      cell: extra.cell ? function (row) {
        return extra.cell(row.entry[key]);
      } : undefined,
      filter: extra.filter
    };
  }

  function rateCell(value) {
    return present(value) ? el("bdi", { class: "v" }, decimal(value)) : missing();
  }

  function truncatedCell(value) {
    return value === true ? badge("truncated", "truncated") : value === false ? "no" : missing("not parsed");
  }

  function versionsCell(value) {
    return list(value).length === 0 ? missing() : el("span", null, list(value).map(function (version) {
      return [mono(version), " "];
    }));
  }

  function licencesRows(data) {
    const counts = obj(data.license_counts);
    return Object.keys(counts).sort().map(function (licence) {
      return { license: licence, components: counts[licence] };
    });
  }

  const PANELS = {
    compliance: compliancePanel,
    tests: function () {
      return genericPanel("tests", [
        dataColumn("Total", "total"), dataColumn("Passed", "passed"), dataColumn("Failed", "failed"),
        dataColumn("Errors", "errors"), dataColumn("Skipped", "skipped"),
        dataColumn("Truncated", "truncated", { cell: truncatedCell })
      ], [{
        title: "Failed and errored test cases",
        pick: function (data) {
          return data.failed_cases;
        },
        columns: [entryColumn("Name", "name"), entryColumn("Class", "classname"),
          entryColumn("Kind", "kind", { cell: function (value) {
            return badge(value === "failure" ? "fail" : "error", plain(value));
          }, filter: true }), entryColumn("Message", "message")]
      }]);
    },
    coverage: function () {
      const parts = genericPanel("coverage", [
        dataColumn("Line rate", "line_rate", { cell: rateCell }),
        dataColumn("Branch rate", "branch_rate", { cell: rateCell }),
        dataColumn("Lines covered", "lines_covered"), dataColumn("Lines valid", "lines_valid"),
        dataColumn("Branches covered", "branches_covered"), dataColumn("Branches valid", "branches_valid"),
        dataColumn("Truncated", "truncated", { cell: truncatedCell })
      ], [{
        title: "Packages",
        pick: function (data) {
          return data.packages;
        },
        columns: [entryColumn("Package", "name"),
          entryColumn("Line rate", "line_rate", { cell: rateCell }),
          entryColumn("Branch rate", "branch_rate", { cell: rateCell })]
      }]);
      parts.splice(2, 0, el("p", null, "Rates are shown as the report gives them, as fractions from 0 to 1."));
      return parts;
    },
    lint: function () {
      return genericPanel("lint", [
        dataColumn("Total", "total"), dataColumn("Lint format", "format"),
        dataColumn("Truncated", "truncated", { cell: truncatedCell })
      ], [{
        title: "Lint issues",
        pick: function (data) {
          return data.issues;
        },
        columns: [entryColumn("Rule", "rule_id", { filter: true }),
          entryColumn("Severity", "severity", { cell: badgeCell, filter: true, rank: rankIn(SEVERITY_ORDER) }),
          entryColumn("Message", "message"),
          entryColumn("Path", "path", { cell: function (value) {
            return mono(value);
          } }),
          entryColumn("Line", "line")]
      }]);
    },
    vulnerabilities: function () {
      return genericPanel("vulnerabilities", [
        dataColumn("Scanner", "scanner"), dataColumn("Scanner version", "scanner_version"),
        dataColumn("Database built", "database_built"), dataColumn("Total", "total"),
        dataColumn("Truncated", "truncated", { cell: truncatedCell })
      ], [{
        title: "Vulnerable packages",
        pick: function (data) {
          return data.vulnerabilities;
        },
        columns: [entryColumn("Vulnerability", "vulnerability_id", { cell: function (value) {
          return mono(value);
        } }),
        entryColumn("Severity", "severity", { cell: badgeCell, filter: true, rank: rankIn(SEVERITY_ORDER) }),
        entryColumn("Package", "package"), entryColumn("Version", "version"),
        entryColumn("Fix state", "fix_state", { filter: true }),
        entryColumn("Fixed versions", "fixed_versions", { cell: versionsCell, sortable: false })]
      }]);
    },
    sbom: function () {
      return genericPanel("sbom", [
        dataColumn("SBOM format", "format"), dataColumn("Specification", "spec_version"),
        dataColumn("Components", "component_count"), dataColumn("Without licence", "unlicensed"),
        dataColumn("Truncated", "truncated", { cell: truncatedCell })
      ], [{
        title: "Licences",
        pick: licencesRows,
        columns: [entryColumn("Licence", "license"), entryColumn("Components", "components")]
      }, {
        title: "Components",
        pick: function (data) {
          return data.components;
        },
        columns: [entryColumn("Name", "name"), entryColumn("Version", "version"),
          entryColumn("Licence", "license", { filter: true })]
      }]);
    },
    molecule: function () {
      return genericPanel("molecule", [
        dataColumn("Total", "total"), dataColumn("Passed", "passed"), dataColumn("Failed", "failed"),
        dataColumn("Skipped", "skipped"), dataColumn("Error", "error")
      ], [{
        title: "Scenarios",
        pick: function (data) {
          return data.scenarios;
        },
        columns: [entryColumn("Scenario", "name", { filter: true }), entryColumn("Platform", "platform", { filter: true }),
          entryColumn("Result", "result", { cell: badgeCell, filter: true })]
      }]);
    },
    packer: function () {
      return genericPanel("packer", [dataColumn("Last run UUID", "last_run_uuid", { cell: function (value) {
        return mono(value);
      } })], [{
        title: "Builds",
        pick: function (data) {
          return data.builds;
        },
        columns: [entryColumn("Name", "name"), entryColumn("Builder", "builder_type", { filter: true }),
          entryColumn("Artifact ID", "artifact_id", { cell: function (value) {
            return mono(value);
          } }),
          entryColumn("Build time", "build_time"),
          entryColumn("Run UUID", "run_uuid", { cell: function (value) {
            return mono(value);
          } }),
          entryColumn("In last run", "in_last_run", { cell: function (value) {
            return value ? "yes" : "no";
          }, filter: true }),
          entryColumn("Files", "files", { sortable: false, cell: function (value) {
            return list(value).length === 0 ? missing() : el("ul", { class: "plain" }, list(value).map(function (file) {
              return el("li", null, [mono(obj(file).name), " ", val(obj(file).size, "size unknown")]);
            }));
          } }),
          entryColumn("Custom data", "custom_data", { sortable: false, cell: function (value) {
            const fields = obj(value);
            const keys = Object.keys(fields).sort();
            return keys.length === 0 ? missing() : pairs(keys.map(function (key) {
              return [el("bdi", { class: "v" }, key), val(fields[key])];
            }));
          } })]
      }]);
    },
    codebuild: function () {
      return genericPanel("codebuild", [], [{
        title: "Builds",
        pick: function (data) {
          return data.builds;
        },
        columns: [entryColumn("Build ID", "build_id", { cell: function (value) {
          return mono(value);
        } }),
        entryColumn("Project", "project", { filter: true }),
        entryColumn("Status", "status", { cell: badgeCell, filter: true }),
        entryColumn("Phase", "phase"),
        entryColumn("Source version", "source_version", { cell: function (value) {
          return mono(value);
        } }),
        entryColumn("Resolved source version", "resolved_source_version", { cell: function (value) {
          return mono(value);
        } }),
        entryColumn("Started", "started_at"), entryColumn("Ended", "ended_at")]
      }]);
    }
  };

  function overviewPanel() {
    const metadata = obj(REPORT.metadata);
    const compliance = obj(SECTIONS.compliance);
    const overview = obj(REPORT.overview);
    const parts = [
      el("h2", null, "Overview"),
      el("p", null, "This dashboard shows scan, test and build results exactly as the report records them. "
        + "It never states compliance with ISO 27001, PCI DSS, NIST, NIS2 or any other framework."),
      pairs([
        ["Scope", [val(scopeLabel()), " (every figure in this report describes this scope)"]],
        ["Schema version", val(REPORT.schema_version)],
        ["Commit", mono(metadata.commit, "not supplied")],
        ["Pull request", val(metadata.pull_request, "not supplied")],
        ["Workflow run", mono(metadata.workflow_run, "not supplied")],
        ["Started", val(metadata.started_at, "not supplied")],
        ["Finished", val(metadata.finished_at, "not supplied")],
        ["Generated", val(metadata.generated_at, "not supplied")]
      ]),
      el("h3", null, "Compliance result")
    ];
    if (isObject(compliance.summary)) {
      parts.push(complianceSummary(compliance.summary, "Compliance summary"));
    } else {
      const status = plain(compliance.status);
      parts.push(callout(status === "error" ? "bad" : status === "available" ? "neutral" : "warn",
        "No compliance summary.",
        el("p", null, status === "available"
          ? "The report covers several benchmarks or content versions, which are never pooled. "
            + "See the Compliance tab for the figures per benchmark and host."
          : ["The compliance section is ", badge(status, SECTION_STATUS_TEXT[status] || status), ". Reason: ",
            val(compliance.reason)])));
    }
    parts.push(el("h3", null, "Sections"));
    parts.push(simpleTable("Section status", ["Section", "Status", "Reason"], SECTION_ORDER.map(function (name) {
      const section = obj(SECTIONS[name]);
      const status = plain(section.status);
      return [sectionTitle(name), badge(status, SECTION_STATUS_TEXT[status] || status), val(section.reason, "none")];
    })));
    const absent = list(overview.unavailable).filter(function (name) {
      return list(obj(SECTIONS[name]).items).length === 0;
    });
    if (absent.length > 0) {
      parts.push(el("h3", null, "Report types not supplied"));
      parts.push(el("p", null, "No input was supplied for these sections, so they have no tab. "
        + "A missing report type is never shown as passed."));
      parts.push(el("ul", null, absent.map(function (name) {
        return el("li", null, sectionTitle(name));
      })));
    }
    return parts;
  }

  function rawPanel() {
    return [
      el("h2", null, "Raw artifacts"),
      el("p", null, "Every input file as supplied, with the SHA-256 of the bytes that were parsed."),
      dataTable({
        caption: "Raw artifacts",
        rows: list(REPORT.raw_artifacts).map(function (artifact) {
          return { entry: obj(artifact) };
        }),
        columns: [
          entryColumn("Path", "path", { cell: function (value) {
            return mono(value);
          } }),
          entryColumn("Format", "format", { filter: true }),
          entryColumn("Status", "status", { cell: badgeCell, filter: true }),
          entryColumn("SHA-256", "sha256", { cell: function (value) {
            return mono(value, "not read");
          } }),
          entryColumn("Size in bytes", "size", { cell: function (value) {
            return val(value, "not read");
          } })
        ]
      })
    ];
  }

  function themeToggle() {
    const root = document.documentElement;
    const query = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
    const button = el("button", { type: "button", class: "theme-toggle", id: "theme-toggle" });
    function effective() {
      const chosen = root.getAttribute("data-theme");
      if (chosen === "light" || chosen === "dark") {
        return chosen;
      }
      return query && query.matches ? "dark" : "light";
    }
    function label() {
      const current = effective();
      button.textContent = current === "dark" ? "Use light theme" : "Use dark theme";
      button.setAttribute("aria-label", "Theme is " + current + ". " + button.textContent);
    }
    button.addEventListener("click", function () {
      root.setAttribute("data-theme", effective() === "dark" ? "light" : "dark");
      label();
    });
    if (query && query.addEventListener) {
      query.addEventListener("change", label);
    }
    label();
    return button;
  }

  function tabs(definitions) {
    const tablist = el("div", { class: "tabs", role: "tablist", "aria-label": "Report sections" });
    const panels = [];
    const buttons = [];
    const rendered = [];
    definitions.forEach(function (definition, index) {
      const tabId = "tab-" + definition.name;
      const panelId = "panel-" + definition.name;
      const button = el("button", {
        type: "button",
        role: "tab",
        id: tabId,
        "aria-controls": panelId,
        "aria-selected": index === 0 ? "true" : "false",
        tabindex: index === 0 ? "0" : "-1"
      }, [definition.label, definition.state ? el("span", { class: "tab-state" }, " (" + definition.state + ")") : null]);
      const panel = el("div", { role: "tabpanel", id: panelId, "aria-labelledby": tabId, tabindex: "0" });
      panel.hidden = index !== 0;
      button.addEventListener("click", function () {
        select(index, false);
      });
      buttons.push(button);
      panels.push(panel);
      rendered.push(false);
      tablist.appendChild(button);
    });
    function render(index) {
      if (!rendered[index]) {
        rendered[index] = true;
        append(panels[index], definitions[index].render());
      }
    }
    function select(index, focus) {
      render(index);
      buttons.forEach(function (button, position) {
        const active = position === index;
        button.setAttribute("aria-selected", active ? "true" : "false");
        button.setAttribute("tabindex", active ? "0" : "-1");
        panels[position].hidden = !active;
      });
      if (focus) {
        buttons[index].focus();
      }
    }
    tablist.addEventListener("keydown", function (event) {
      const current = buttons.indexOf(document.activeElement);
      if (current < 0) {
        return;
      }
      let target = -1;
      if (event.key === "ArrowRight") {
        target = (current + 1) % buttons.length;
      } else if (event.key === "ArrowLeft") {
        target = (current - 1 + buttons.length) % buttons.length;
      } else if (event.key === "Home") {
        target = 0;
      } else if (event.key === "End") {
        target = buttons.length - 1;
      }
      if (target >= 0) {
        event.preventDefault();
        select(target, true);
      }
    });
    window.addEventListener("beforeprint", function () {
      definitions.forEach(function (_definition, index) {
        render(index);
      });
    });
    render(0);
    return [tablist].concat(panels);
  }

  function start() {
    const banner = document.getElementById("banner");
    const main = document.getElementById("main");
    const footer = document.getElementById("footer");
    if (!banner || !main || !footer) {
      return;
    }
    const text = el("div", { class: "banner-text" });
    while (banner.firstChild) {
      text.appendChild(banner.firstChild);
    }
    banner.appendChild(text);
    banner.appendChild(themeToggle());
    if (!isObject(DATA.report)) {
      main.replaceChildren(callout("bad", "The embedded report could not be read.",
        el("p", null, "Nothing in this file can be shown as a result.")));
      return;
    }
    text.appendChild(el("p", { class: "meta" }, [
      "Scope: ", val(scopeLabel()), ". Schema version ", val(REPORT.schema_version), "."
    ]));
    const definitions = [{ name: "overview", label: "Overview", render: overviewPanel }];
    SECTION_ORDER.forEach(function (name) {
      const section = obj(SECTIONS[name]);
      if (list(section.items).length === 0) {
        return;
      }
      const status = plain(section.status);
      definitions.push({
        name: name,
        label: sectionTitle(name),
        state: status === "available" ? null : status,
        render: PANELS[name]
      });
    });
    definitions.push({ name: "raw", label: "Raw artifacts", render: rawPanel });
    main.replaceChildren.apply(main, tabs(definitions));
    footer.appendChild(el("p", null, "Self-contained report dashboard. It makes no network requests; all data is "
      + "embedded in this file and rendered as text."));
  }

  start();
})();
