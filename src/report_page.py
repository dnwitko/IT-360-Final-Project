"""The HTML, CSS and JavaScript added around the vis-network graph to make the report page.

The page has three tabs: the timeline graph, the full list of suspicious activity, and
the files that need manual review. All log text is inserted with textContent (never
innerHTML), so text written by an attacker can't run as HTML."""

STYLE = """
<style>
  body { margin: 0; background: #222; color: #eee; font-family: Segoe UI, Arial, sans-serif; }
  .card { border: none !important; background: #222 !important; }
  #report-header { padding: 12px 16px 0; border-bottom: 1px solid #444; }
  #report-header h1 { font-size: 20px; font-weight: 600; margin: 0 0 10px; }
  .tabs button { background: none; border: none; color: #bbb; font-size: 15px; padding: 8px 14px;
                 cursor: pointer; border-bottom: 3px solid transparent; }
  .tabs button.active { color: #fff; border-bottom-color: #5b8def; }
  .tabs button.alert { color: #ff8a8d; }
  .view { padding: 12px 16px; line-height: 1.45; }
  .intro { max-width: 900px; margin: 0 0 8px; }
  ul.intro { padding-left: 20px; }
  .toolbar { margin-top: 8px; }
  .toolbar button, .entry button, #details-actions button {
      background: #3a3a3a; color: #eee; border: 1px solid #666; border-radius: 4px; padding: 4px 10px;
      cursor: pointer; font-size: 13px; margin-right: 6px; }
  #details-actions button { background: #e8e6dc; color: #111; border-color: #aaa; margin-top: 10px; }
  .filters select, .filters input { background: #333; color: #eee; border: 1px solid #666; border-radius: 4px;
      padding: 4px 6px; margin-right: 8px; font-size: 14px; max-width: 320px; }
  .entry { background: #2c2c2c; border-left: 4px solid #e5484d; border-radius: 4px; padding: 10px 14px;
           margin: 10px 0; max-width: 1000px; }
  .entry.highlight { outline: 2px solid #fff; }
  .entry .when { color: #ff8a8d; font-family: Consolas, monospace; margin-right: 8px; }
  .entry .what { font-weight: 600; }
  .entry .muted { color: #aaa; }
  .entry ul { margin: 4px 0 6px 0; padding-left: 20px; }
  .chip { display: inline-block; background: #444; border-radius: 10px; padding: 1px 9px; margin: 2px 4px 2px 0;
          font-size: 13px; cursor: help; }
  .flagged { border-left-color: #f5a623; }
  .flagged .path { font-family: Consolas, monospace; font-weight: 600; word-break: break-all; }
</style>
"""

HEADER = """
<div id="report-header">
  <h1>L.A.A.S.T Event Graph and Report</h1>
  <div class="tabs">
    <button id="tab-timeline" class="active" onclick="showTab('timeline')">Timeline</button>
    <button id="tab-suspicious" onclick="showTab('suspicious')">Suspicious activity</button>
    <button id="tab-review" onclick="showTab('review')">Needs manual review</button>
  </div>
</div>
<div id="view-timeline" class="view">
  <ul class="intro">
    <li>Each row is one log file. Events run left to right, oldest first.</li>
    <li>Repeated events are combined into one circle with a count, such as x110. Larger circles mean more repeats.</li>
    <li>Hover over a circle for a summary. Click it for full details.</li>
    <li id="gap-note" style="display: none;">Gray circles stand for less important events, hidden to keep long files short.
        Click one to see what it contains.</li>
    <li>Scroll to zoom. Drag to pan.</li>
  </ul>
  <div>
    <span style="color: %(suspicious)s;">&#9679;</span> Suspicious &nbsp;&nbsp;
    <span style="color: %(notable)s;">&#9679;</span> Worth noting &nbsp;&nbsp;
    <span style="color: %(routine)s;">&#9679;</span> Routine &nbsp;&nbsp;
    <span style="color: %(gap)s;">&#9679;</span> Hidden stretch of events
  </div>
  <div class="toolbar"><button id="toggle-gaps" onclick="toggleAllGaps()" style="display: none;">Show hidden steps</button></div>
</div>
<div id="details" style="display: none; position: fixed; top: 16px; right: 16px; width: 380px; max-height: 80vh;
     overflow: auto; background: #f5f4ed; color: #111; border-radius: 6px; padding: 14px 16px; z-index: 10;
     font-size: 14px; box-shadow: 0 4px 16px rgba(0,0,0,.5);">
  <button onclick="document.getElementById('details').style.display='none'"
          style="float: right; border: none; background: none; font-size: 18px; cursor: pointer;">&times;</button>
  <div id="details-text" style="white-space: pre-wrap; line-height: 1.4;"></div>
  <div id="details-actions"></div>
</div>
"""

OTHER_VIEWS = """
<div id="view-suspicious" class="view" style="display: none;">
  <div class="intro">
    Events that match known attack behavior, oldest first. Repeated events of the same kind are grouped into
    one entry. Hover over a technique for a description, or select Show on timeline to see the surrounding events.
  </div>
  <div class="filters">
    <select id="filter-file"><option value="">All files</option></select>
    <select id="filter-technique"><option value="">All techniques</option></select>
    <input id="filter-text" type="search" placeholder="Search">
  </div>
  <div id="suspicious-count" class="muted" style="margin-top: 10px;"></div>
  <div id="suspicious-list"></div>
</div>
<div id="view-review" class="view" style="display: none;">
  <div class="intro">
    Files and folders that could not be fully analyzed. Their events are missing or incomplete in this report,
    so review them manually. A damaged, empty or unreadable log can itself be a sign of tampering.
  </div>
  <div id="review-list"></div>
</div>
"""

SCRIPT = r"""
<script>
var REPORT = __REPORT_DATA__;
var openGaps = {};

function byId(id) { return document.getElementById(id); }

function element(tag, className, text) {
    var el = document.createElement(tag);
    if (className) { el.className = className; }
    if (text !== undefined) { el.textContent = text; }
    return el;
}

// ---------- Tabs ----------
function showTab(name) {
    ["timeline", "suspicious", "review"].forEach(function (tab) {
        byId("view-" + tab).style.display = tab === name ? "block" : "none";
        byId("tab-" + tab).classList.toggle("active", tab === name);
    });
    var card = document.querySelector(".card");
    if (card) { card.style.display = name === "timeline" ? "block" : "none"; }
    if (name !== "timeline") { byId("details").style.display = "none"; }
    else if (window.network) { network.redraw(); }
}

// ---------- Timeline ----------
// The nodes of one row, left to right, with open hidden stretches drawn in full
function rowNodes(row) {
    var list = [row.file];
    row.items.forEach(function (item) {
        if (item.hidden && openGaps[item.node.id]) { list = list.concat(item.hidden); }
        else { list.push(item.node); }
    });
    return list;
}

function render() {
    var nodeList = [], edgeList = [];
    REPORT.rows.forEach(function (row) {
        var list = rowNodes(row);
        list.forEach(function (node, i) {
            nodeList.push(Object.assign({}, node, { level: i }));
            // Dashed lines mark steps that are normally hidden
            if (i) { edgeList.push({ from: list[i - 1].id, to: node.id, dashes: !!(node.gap || list[i - 1].gap) }); }
        });
    });
    nodes = new vis.DataSet(nodeList);
    edges = new vis.DataSet(edgeList);
    network.setData({ nodes: nodes, edges: edges });
}

// Fitting a big graph to the screen makes it too small to read, so start zoomed in
// on the top-left (the start of the rows) instead
function startView() {
    network.fit();
    if (network.getScale() >= 0.6 || !nodes.length) { return; }
    var boxes = nodes.getIds().map(function (id) { return network.getBoundingBox(id); });
    var minX = Math.min.apply(null, boxes.map(function (b) { return b.left; }));
    var minY = Math.min.apply(null, boxes.map(function (b) { return b.top; }));
    var box = byId("mynetwork").getBoundingClientRect();
    var scale = 0.75;
    network.moveTo({ scale: scale, position: { x: minX - 20 + box.width / 2 / scale,
                                               y: minY - 20 + box.height / 2 / scale } });
}

function focusOn(id) {
    if (!nodes.get(id)) { return; }
    network.selectNodes([id]);
    network.focus(id, { scale: Math.max(network.getScale(), 0.9), animation: { duration: 400 } });
    showDetails(nodes.get(id));
}

function setGap(gapId, open) {
    if (open) { openGaps[gapId] = true; } else { delete openGaps[gapId]; }
    render();
    updateToggle();
}

function gapIds() {
    var ids = [];
    REPORT.rows.forEach(function (row) {
        row.items.forEach(function (item) { if (item.hidden) { ids.push(item.node.id); } });
    });
    return ids;
}

function updateToggle() {
    var ids = gapIds(), button = byId("toggle-gaps");
    button.style.display = ids.length ? "inline-block" : "none";
    var allOpen = ids.length && ids.every(function (id) { return openGaps[id]; });
    button.textContent = allOpen ? "Hide them again" : "Show hidden steps";
}

function toggleAllGaps() {
    var ids = gapIds();
    var allOpen = ids.every(function (id) { return openGaps[id]; });
    openGaps = {};
    if (!allOpen) { ids.forEach(function (id) { openGaps[id] = true; }); }
    byId("details").style.display = "none";
    render();
    updateToggle();
    startView();
}

function addAction(label, onClick) {
    var button = element("button", "", label);
    button.onclick = onClick;
    byId("details-actions").appendChild(button);
}

function showDetails(item) {
    var panel = byId("details");
    if (!item || !item.details) { panel.style.display = "none"; return; }
    byId("details-text").textContent = item.details;
    byId("details-actions").textContent = "";
    if (item.kind === "gap" && item.expandable) {
        addAction("Show these steps", function () { setGap(item.id, true); focusOn(item.first); });
    }
    if (item.gap) {
        addAction("Hide this stretch again", function () { setGap(item.gap, false); focusOn(item.gap); });
    }
    if (item.entries && item.entries.length) {
        addAction("See it in the suspicious activity list", function () { showEntries(item.entries); });
    }
    panel.style.display = "block";
}

// ---------- Suspicious activity ----------
function fillFilters() {
    var files = {}, techniques = {};
    REPORT.entries.forEach(function (entry) {
        files[entry.file] = true;
        entry.techniques.forEach(function (t) { techniques[t.id] = t.label; });
    });
    Object.keys(files).sort().forEach(function (file) {
        var option = element("option", "", file);
        option.value = file;
        byId("filter-file").appendChild(option);
    });
    Object.keys(techniques).sort(function (a, b) { return techniques[a].localeCompare(techniques[b]); })
        .forEach(function (id) {
            var option = element("option", "", techniques[id]);
            option.value = id;
            byId("filter-technique").appendChild(option);
        });
    ["filter-file", "filter-technique", "filter-text"].forEach(function (id) {
        byId(id).addEventListener("input", renderEntries);
    });
}

function renderEntries() {
    var file = byId("filter-file").value, technique = byId("filter-technique").value;
    var text = byId("filter-text").value.toLowerCase();
    var list = byId("suspicious-list"), shown = 0;
    list.textContent = "";
    REPORT.entries.forEach(function (entry, index) {
        if (file && entry.file !== file) { return; }
        if (technique && !entry.techniques.some(function (t) { return t.id === technique; })) { return; }
        if (text && entry.search.indexOf(text) < 0) { return; }
        shown++;
        var card = element("div", "entry");
        card.id = "entry-" + index;
        var head = element("div");
        head.appendChild(element("span", "when", entry.time || "no time"));
        head.appendChild(element("span", "what", entry.sentence + (entry.repeat > 1 ? " (x" + entry.repeat + ")" : "")));
        card.appendChild(head);
        if (entry.similar.length) {
            card.appendChild(element("div", "muted", "Also: " + entry.similar.join("; ")));
        }
        card.appendChild(element("div", "muted", "Where: " + entry.file + (entry.host ? ", on " + entry.host : "")));
        card.appendChild(element("div", "", "Why it's suspicious:"));
        var reasons = element("ul");
        entry.reasons.forEach(function (reason) { reasons.appendChild(element("li", "", reason)); });
        card.appendChild(reasons);
        if (entry.techniques.length) {
            var chips = element("div");
            entry.techniques.forEach(function (t) {
                var chip = element("span", "chip", t.label);
                chip.title = t.text;
                chips.appendChild(chip);
            });
            card.appendChild(chips);
        }
        if (entry.node) {
            var button = element("button", "", "Show on timeline");
            button.style.marginTop = "6px";
            button.onclick = function () { showOnTimeline(entry); };
            card.appendChild(button);
        }
        list.appendChild(card);
    });
    var total = REPORT.entries.length;
    byId("suspicious-count").textContent = !total ? "Nothing suspicious was found."
        : shown === total ? total + " entries (" + REPORT.event_count + " suspicious events in all)"
        : "Showing " + shown + " of " + total + " entries";
}

function showOnTimeline(entry) {
    showTab("timeline");
    if (entry.gap && !openGaps[entry.gap]) { setGap(entry.gap, true); }
    focusOn(entry.node);
}

function showEntries(indexes) {
    byId("filter-file").value = "";
    byId("filter-technique").value = "";
    byId("filter-text").value = "";
    renderEntries();
    showTab("suspicious");
    indexes.forEach(function (index, i) {
        var card = byId("entry-" + index);
        if (!card) { return; }
        card.classList.add("highlight");
        setTimeout(function () { card.classList.remove("highlight"); }, 3000);
        if (!i) { card.scrollIntoView({ block: "center" }); }
    });
}

// ---------- Needs manual review ----------
function renderReview() {
    var list = byId("review-list");
    if (!REPORT.flagged.length) {
        list.appendChild(element("div", "muted", "All files were read completely."));
        return;
    }
    REPORT.flagged.forEach(function (item) {
        var card = element("div", "entry flagged");
        card.appendChild(element("div", "path", item.file));
        card.appendChild(element("div", "", item.error));
        list.appendChild(card);
    });
}

function setUpReport() {
    byId("tab-suspicious").textContent = "Suspicious activity (" + REPORT.entries.length + ")";
    byId("tab-review").textContent = "Needs manual review (" + REPORT.flagged.length + ")";
    if (REPORT.flagged.length) { byId("tab-review").classList.add("alert"); }
    if (REPORT.has_gaps) {
        byId("gap-note").style.display = "list-item";
    }
    fillFilters();
    renderEntries();
    renderReview();
    network.on("click", function (params) {
        showDetails(params.nodes.length ? nodes.get(params.nodes[0]) : null);
    });
    render();
    updateToggle();
    startView();
}
</script>
"""
