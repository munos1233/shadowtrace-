/** ReportToc — table of contents with scroll-spy highlighting (ISSUE-074). */

import { useEffect, useState } from "react";
import { Anchor, Typography } from "antd";
import { CHAPTER_KEYS } from "../../utils/exportMarkdown";
import type { InvestigationReport } from "../../types/report";

const { Text } = Typography;

interface ReportTocProps {
  report: InvestigationReport;
}

export default function ReportToc({ report }: ReportTocProps) {
  const [activeKey, setActiveKey] = useState<string>(CHAPTER_KEYS[0]);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setActiveKey(entry.target.id);
          }
        }
      },
      { rootMargin: "-10% 0px -80% 0px" },
    );

    for (const key of CHAPTER_KEYS) {
      const el = document.getElementById(key);
      if (el) observer.observe(el);
    }

    return () => observer.disconnect();
  }, [report.report_id]);

  const items = CHAPTER_KEYS
    .filter((k) => report.sections.some((s) => s.key === k && s.title))
    .map((k) => {
      const section = report.sections.find((s) => s.key === k)!;
      return {
        key: k,
        href: `#${k}`,
        title: <Text ellipsis style={{ fontSize: 13 }}>{section.title}</Text>,
      };
    });

  return (
    <div style={{ width: 200, flexShrink: 0, position: "sticky", top: 16 }}>
      <Text strong style={{ fontSize: 14, marginBottom: 8, display: "block" }}>
        目录
      </Text>
      <Anchor
        items={items}
        getCurrentAnchor={() => `#${activeKey}`}
        onClick={(e, link) => {
          e.preventDefault();
          const el = document.getElementById(link.href.replace("#", ""));
          if (el) el.scrollIntoView({ behavior: "smooth" });
        }}
      />
    </div>
  );
}
