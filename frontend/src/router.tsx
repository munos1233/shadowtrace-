/** Application router (ISSUE-067 / ISSUE-085). */

import { createBrowserRouter } from "react-router-dom";
import MainLayout from "./layouts/MainLayout";
import EventListPage from "./pages/EventListPage";
import EventDetailPage from "./pages/EventDetailPage";
import ApprovalPage from "./pages/ApprovalPage";
import ToolAuditPage from "./pages/ToolAuditPage";
import SocDashboardPage from "./pages/SocDashboardPage";
import SocDashboardErrorPage from "./pages/SocDashboardErrorPage";
import KnowledgeReviewPage from "./pages/KnowledgeReviewPage";
import DetectionGovernancePage from "./pages/DetectionGovernancePage";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <MainLayout />,
    children: [
      { index: true, element: <EventListPage /> },
      { path: "events", element: <EventListPage /> },
      { path: "events/:eventId", element: <EventDetailPage /> },
      { path: "approvals", element: <ApprovalPage /> },
      { path: "tools-audit", element: <ToolAuditPage /> },
      { path: "knowledge/reviews", element: <KnowledgeReviewPage /> },
      { path: "detection/governance", element: <DetectionGovernancePage /> },
    ],
  },
  // Isolated from MainLayout so SOC wall / missing page cannot break other routes.
  {
    path: "/dashboard",
    element: <SocDashboardPage />,
    errorElement: <SocDashboardErrorPage />,
  },
]);
