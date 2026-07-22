/** apiClient + eventApi integration tests (ISSUE-067). */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  ApiError,
  setApiErrorToastHandler,
  showApiErrorToast,
} from "../../src/services/apiClient";
import * as eventApi from "../../src/services/eventApi";

const mockGet = vi.fn();
const mockPost = vi.fn();
const mockPut = vi.fn();

vi.mock("../../src/services/apiClient", async () => {
  const actual = await vi.importActual<
    typeof import("../../src/services/apiClient")
  >("../../src/services/apiClient");
  return {
    ...actual,
    default: {
      get: (...args: unknown[]) => mockGet(...args),
      post: (...args: unknown[]) => mockPost(...args),
      put: (...args: unknown[]) => mockPut(...args),
    },
    apiClient: {
      get: (...args: unknown[]) => mockGet(...args),
      post: (...args: unknown[]) => mockPost(...args),
      put: (...args: unknown[]) => mockPut(...args),
    },
  };
});

describe("ApiError", () => {
  it("carries error_code and message from payload", () => {
    const err = new ApiError({
      error_code: "not_found",
      error_message: "Event not found",
    });
    expect(err.error_code).toBe("not_found");
    expect(err.message).toBe("Event not found");
    expect(err.name).toBe("ApiError");
  });
});

describe("apiClient toast handler", () => {
  it("uses injectable handler for error messages", () => {
    const toast = vi.fn();
    setApiErrorToastHandler(toast);
    showApiErrorToast("test error");
    expect(toast).toHaveBeenCalledWith("test error");
  });
});

describe("eventApi", () => {
  beforeEach(() => {
    mockGet.mockReset();
    mockPost.mockReset();
    mockPut.mockReset();
    mockGet.mockResolvedValue({ data: {} });
    mockPost.mockResolvedValue({ data: {} });
    mockPut.mockResolvedValue({ data: {} });
  });

  it("listEvents calls GET /events", async () => {
    await eventApi.listEvents({ page: 1 });
    expect(mockGet).toHaveBeenCalledWith("/events", { params: { page: 1 } });
  });

  it("getEvent calls GET /events/:id", async () => {
    await eventApi.getEvent("evt-1");
    expect(mockGet).toHaveBeenCalledWith("/events/evt-1");
  });

  it("getSourceRecord calls GET /source-records/:id", async () => {
    await eventApi.getSourceRecord("sr-1");
    expect(mockGet).toHaveBeenCalledWith("/source-records/sr-1");
  });

  it("getExecutionJob calls GET /execution-jobs/:id", async () => {
    await eventApi.getExecutionJob("job-1");
    expect(mockGet).toHaveBeenCalledWith("/execution-jobs/job-1");
  });

  it("resolveUnknownAction calls POST /actions/:id/resolve-unknown", async () => {
    const body = {
      resolution: "manual_confirmed" as const,
      comment: "verified manually",
    };
    await eventApi.resolveUnknownAction("act-1", body);
    expect(mockPost).toHaveBeenCalledWith(
      "/actions/act-1/resolve-unknown",
      body,
    );
  });

  it("approveAction calls POST /actions/:id/approve", async () => {
    await eventApi.approveAction("act-1");
    expect(mockPost).toHaveBeenCalledWith("/actions/act-1/approve");
  });
});
