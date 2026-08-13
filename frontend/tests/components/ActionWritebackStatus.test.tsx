/** ActionWritebackStatus component tests (ISSUE-331). */

import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import ActionWritebackStatus from "../../src/components/event/ActionWritebackStatus";

describe("ActionWritebackStatus", () => {
  it("renders neutral label for entity side-effect obligation", () => {
    render(
      <ActionWritebackStatus
        writeback_required
        writeback_applicable={false}
        writeback_status={null}
        data-testid="entity-writeback"
      />,
    );
    expect(screen.getByTestId("entity-writeback")).toHaveTextContent("不承担终态写回");
    expect(screen.queryByText("终态写回已确认")).not.toBeInTheDocument();
  });

  it("renders success only for applicable confirmed writeback", () => {
    render(
      <ActionWritebackStatus
        writeback_required
        writeback_applicable
        writeback_status="confirmed"
        data-testid="terminal-writeback"
      />,
    );
    expect(screen.getByTestId("terminal-writeback")).toHaveTextContent("终态写回已确认");
  });
});
