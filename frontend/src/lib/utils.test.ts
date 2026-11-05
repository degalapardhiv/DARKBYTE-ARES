import { describe, expect, it } from "vitest";
import type { Assessment } from "./types";
import {
  assessmentTone,
  cn,
  countSeverities,
  formatBytes,
  formatDate,
  initials,
  moduleLabel,
  parseCommaList,
  parsePortList,
  percent,
  riskColor,
  riskLabel,
  safeJsonParse,
  severityFromScore,
  severityRank,
  timeAgo,
  truncate,
} from "./utils";

describe("class and text helpers", () => {
  it("joins truthy classes and drops empty values", () => {
    expect(cn("panel", false, undefined, null, "active")).toBe("panel active");
  });

  it("truncates only strings above the limit", () => {
    expect(truncate("short", 10)).toBe("short");
    expect(truncate("abcdefghij", 5)).toBe("abcd…");
  });

  it("derives initials from the first two words", () => {
    expect(initials("Morgan Vale")).toBe("MV");
    expect(initials("darkbytehunter")).toBe("D");
    expect(initials("  ")).toBe("");
  });

  it("formats bytes with binary units and clamps invalid input", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(-10)).toBe("0 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
  });
});

describe("dates", () => {
  it("returns a placeholder for missing or invalid dates", () => {
    expect(formatDate(null)).toBe("—");
    expect(formatDate("not-a-date")).toBe("—");
    expect(timeAgo(null)).toBe("unknown");
    expect(timeAgo("not-a-date")).toBe("unknown");
  });

  it("describes recent timestamps", () => {
    expect(timeAgo(new Date().toISOString())).toBe("just now");
    expect(timeAgo(new Date(Date.now() - 5 * 60_000).toISOString())).toMatch(/^\d+m ago$/);
    expect(timeAgo(new Date(Date.now() - 2 * 3_600_000).toISOString())).toMatch(/^\d+h ago$/);
  });
});

describe("risk and severity helpers", () => {
  it("maps scores to severity bands", () => {
    expect(severityFromScore(null)).toBe("info");
    expect(severityFromScore(0)).toBe("info");
    expect(severityFromScore(0.1)).toBe("low");
    expect(severityFromScore(4)).toBe("medium");
    expect(severityFromScore(7)).toBe("high");
    expect(severityFromScore(9.8)).toBe("critical");
  });

  it("maps risk colours and labels", () => {
    expect(riskColor(95)).toBe("#FF3B5C");
    expect(riskColor(65)).toBe("#FF7A45");
    expect(riskColor(45)).toBe("#FFB020");
    expect(riskColor(10)).toBe("#38BDF8");
    expect(riskColor(0)).toBe("#64748B");
    expect(riskLabel(95)).toBe("Severe");
    expect(riskLabel(65)).toBe("Elevated");
    expect(riskLabel(45)).toBe("Moderate");
    expect(riskLabel(10)).toBe("Guarded");
    expect(riskLabel(0)).toBe("Baseline");
  });

  it("counts every severity bucket, including zeroes", () => {
    expect(
      countSeverities([
        { severity: "critical" },
        { severity: "critical" },
        { severity: "low" },
        { severity: "info" },
      ]),
    ).toEqual({ critical: 2, high: 0, medium: 0, low: 1, info: 1 });
  });

  it("orders severity values from critical downwards", () => {
    expect(severityRank("critical")).toBeGreaterThan(severityRank("high"));
    expect(severityRank("info")).toBe(1);
  });

  it("colours assessments according to lifecycle state", () => {
    const base = {
      id: "a1",
      name: "Demo",
      module: "recon",
      target_id: "t1",
      config: {},
      progress: 100,
      summary: {},
      is_demo: true,
      created_by: "u1",
      created_at: new Date().toISOString(),
    } as Assessment;

    expect(assessmentTone({ ...base, status: "completed", risk_score: 88 })).toBe("#FF3B5C");
    expect(assessmentTone({ ...base, status: "failed", risk_score: 0 })).toBe("#FF3B5C");
    expect(assessmentTone({ ...base, status: "running", risk_score: 0 })).toBe("#00E5FF");
    expect(assessmentTone({ ...base, status: "draft", risk_score: 0 })).toBe("#64748B");
  });
});

describe("parsing helpers", () => {
  it("parses comma and newline separated lists", () => {
    expect(parseCommaList("a, b\nc,, d")).toEqual(["a", "b", "c", "d"]);
    expect(parseCommaList("  ")).toEqual([]);
  });

  it("expands port ranges, deduplicates and sorts", () => {
    expect(parsePortList("443, 80, 80, 8000-8002")).toEqual([80, 443, 8000, 8001, 8002]);
    expect(parsePortList("0, 65536, 22")).toEqual([22]);
    expect(parsePortList("9000-8999")).toEqual([]);
  });

  it("caps ranges at 513 entries to prevent runaway input", () => {
    expect(parsePortList("1-1000")).toHaveLength(513);
  });

  it("returns typed results from safe JSON parsing", () => {
    expect(safeJsonParse<{ ok: boolean }>('{"ok":true}')).toEqual({ ok: true, data: { ok: true } });
    const failure = safeJsonParse("{not json");
    expect(failure.ok).toBe(false);
    if (!failure.ok) expect(failure.error.length).toBeGreaterThan(0);
  });

  it("calculates bounded percentages", () => {
    expect(percent(5, 10)).toBe(50);
    expect(percent(1, 0)).toBe(0);
    expect(percent(20, 10)).toBe(100);
  });

  it("humanises module identifiers with metadata fallbacks", () => {
    expect(moduleLabel("recon")).toBe("Reconnaissance");
    expect(moduleLabel("custom_module")).toBe("Custom Module");
  });
});
