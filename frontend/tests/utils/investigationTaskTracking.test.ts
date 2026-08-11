import { describe, it, expect } from "vitest";
import {
  isCeleryTaskMode,
  isTerminalTaskState,
  labelTaskState,
  normalizeTaskState,
} from "../../src/utils/investigationTaskTracking";

describe("investigationTaskTracking", () => {
  it("detects celery task mode case-insensitively", () => {
    expect(isCeleryTaskMode("celery")).toBe(true);
    expect(isCeleryTaskMode(" CELERY ")).toBe(true);
    expect(isCeleryTaskMode("background")).toBe(false);
    expect(isCeleryTaskMode(undefined)).toBe(false);
  });

  it("normalizes public task states", () => {
    expect(normalizeTaskState("started")).toBe("STARTED");
    expect(normalizeTaskState("")).toBe("PENDING");
  });

  it("marks SUCCESS/FAILURE/UNKNOWN as terminal", () => {
    expect(isTerminalTaskState("SUCCESS")).toBe(true);
    expect(isTerminalTaskState("FAILURE")).toBe(true);
    expect(isTerminalTaskState("UNKNOWN")).toBe(true);
    expect(isTerminalTaskState("PENDING")).toBe(false);
    expect(isTerminalTaskState("STARTED")).toBe(false);
  });

  it("labels task states for UI", () => {
    expect(labelTaskState("STARTED")).toBe("执行中");
    expect(labelTaskState("UNKNOWN")).toBe("状态未知");
  });
});
