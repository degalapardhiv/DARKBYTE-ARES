import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { useAuth } from "./context/AuthContext";
import { PageLoader } from "./components/ui";
import { Login } from "./pages/Login";
import { Register } from "./pages/Register";
import { Dashboard } from "./pages/Dashboard";
import { Assessments } from "./pages/Assessments";
import { AssessmentDetail } from "./pages/AssessmentDetail";
import { Findings } from "./pages/Findings";
import { Reports } from "./pages/Reports";
import { Targets } from "./pages/Targets";
import { Mitre } from "./pages/Mitre";
import { Notifications } from "./pages/Notifications";
import { Settings } from "./pages/Settings";
import { Audit } from "./pages/Audit";
import { Plugins } from "./pages/Plugins";
import { NotFound } from "./pages/NotFound";
import { ModulePage } from "./pages/modules/ModulePage";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <PageLoader label="Validating session" />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

function PublicOnly({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <PageLoader label="Validating session" />
      </div>
    );
  }
  if (user) return <Navigate to="/" replace />;
  return <>{children}</>;
}

export function App() {
  return (
    <Routes>
      <Route
        path="/login"
        element={
          <PublicOnly>
            <Login />
          </PublicOnly>
        }
      />
      <Route
        path="/register"
        element={
          <PublicOnly>
            <Register />
          </PublicOnly>
        }
      />
      <Route
        element={
          <ProtectedRoute>
            <AppShell />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="assessments" element={<Assessments />} />
        <Route path="assessments/:assessmentId" element={<AssessmentDetail />} />
        <Route path="findings" element={<Findings />} />
        <Route path="reports" element={<Reports />} />
        <Route path="targets" element={<Targets />} />
        <Route path="modules/:moduleId" element={<ModulePage />} />
        <Route path="mitre" element={<Mitre />} />
        <Route path="notifications" element={<Notifications />} />
        <Route path="settings" element={<Settings />} />
        <Route path="audit" element={<Audit />} />
        <Route path="plugins" element={<Plugins />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
