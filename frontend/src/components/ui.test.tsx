import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ImageWithFallback } from "./ImageWithFallback";
import { SeverityBadge, StatusBadge, DemoBadge, RiskPill } from "./Badges";
import { Toggle } from "./ui";
import { NAV_GROUPS, MODULE_META } from "../lib/constants";

describe("Toggle", () => {
  it("exposes switch semantics and emits the opposite value", () => {
    const onChange = vi.fn();
    render(<Toggle checked={false} onChange={onChange} label="Subdomains" description="Resolve labels" />);

    const control = screen.getByRole("switch", { name: /subdomains/i });
    expect(control).toHaveAttribute("aria-checked", "false");
    fireEvent.click(control);
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it("does not fire while disabled", () => {
    const onChange = vi.fn();
    render(<Toggle checked onChange={onChange} label="Locked" disabled />);

    fireEvent.click(screen.getByRole("switch", { name: /locked/i }));
    expect(onChange).not.toHaveBeenCalled();
  });
});

describe("badges", () => {
  it("renders severity labels", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("renders known and custom status labels", () => {
    render(
      <>
        <StatusBadge status="completed" />
        <StatusBadge status="awaiting_review" />
      </>,
    );
    expect(screen.getByText("Completed")).toBeInTheDocument();
    expect(screen.getByText("awaiting review")).toBeInTheDocument();
  });

  it("renders demo and risk indicators", () => {
    render(
      <>
        <DemoBadge />
        <RiskPill score={72.4} />
      </>,
    );
    expect(screen.getByText("Demo dataset")).toBeInTheDocument();
    expect(screen.getByText("72.4")).toBeInTheDocument();
  });
});

describe("ImageWithFallback", () => {
  it("swaps to the fallback asset before showing a placeholder", () => {
    render(<ImageWithFallback src="/assets/missing.webp" alt="Recon visual" fallbackSrc="/assets/ares-logo.png" />);

    const image = screen.getByRole("img", { name: "Recon visual" }) as HTMLImageElement;
    fireEvent.error(image);
    expect(image.src).toContain("/assets/ares-logo.png");

    fireEvent.error(image);
    const placeholder = screen.getByRole("img", { name: "Recon visual" });
    expect(placeholder).not.toHaveProperty("src");
    expect(placeholder).toHaveTextContent("Recon visual");
  });
});

describe("navigation contract", () => {
  it("links all ten functional modules", () => {
    const modulePaths = NAV_GROUPS.flatMap((group) => group.items)
      .map((item) => item.path)
      .filter((path) => path.startsWith("/modules/"));
    expect(modulePaths).toHaveLength(10);
    expect(new Set(modulePaths).size).toBe(10);
    for (const meta of Object.values(MODULE_META)) {
      expect(modulePaths).toContain(meta.path);
    }
  });

  it("keeps the sidebar at fifteen primary entries", () => {
    const primary = NAV_GROUPS.flatMap((group) => group.items);
    expect(primary).toHaveLength(15);
  });
});
