(function () {
  const q = (sel, root = document) => root.querySelector(sel);
  const qa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // Modules select all/none per scope
  qa("[data-module-scope]").forEach((scope) => {
    const allBtn = q("[data-modules-all]", scope);
    const noneBtn = q("[data-modules-none]", scope);
    const boxes = qa("input[type='checkbox'][name='modules']", scope);

    const setAll = (v) => boxes.forEach((b) => (b.checked = v));

    allBtn?.addEventListener("click", (e) => {
      e.preventDefault();
      setAll(true);
    });
    noneBtn?.addEventListener("click", (e) => {
      e.preventDefault();
      setAll(false);
    });
  });

  // Domain table filter
  const filter = q("#domainFilter");
  const table = q("#domainsTable");
  if (filter && table) {
    const rows = qa("tbody tr", table);
    filter.addEventListener("input", () => {
      const val = (filter.value || "").trim().toLowerCase();
      rows.forEach((tr) => {
        const domain = tr.getAttribute("data-domain") || "";
        tr.style.display = domain.includes(val) ? "" : "none";
      });
    });
  }
})();
