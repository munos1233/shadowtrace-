/** ReportExportButtons — download Markdown + print (ISSUE-074). */

import { Button, Space } from "antd";
import { DownloadOutlined, PrinterOutlined } from "@ant-design/icons";
import { downloadReportMarkdown } from "../../utils/exportMarkdown";
import type { InvestigationReport } from "../../types/report";

interface ReportExportButtonsProps {
  report: InvestigationReport;
}

export default function ReportExportButtons({ report }: ReportExportButtonsProps) {
  return (
    <Space>
      <Button
        icon={<DownloadOutlined />}
        onClick={() => downloadReportMarkdown(report)}
      >
        下载 Markdown
      </Button>
      <Button icon={<PrinterOutlined />} onClick={() => window.print()}>
        打印
      </Button>
    </Space>
  );
}
