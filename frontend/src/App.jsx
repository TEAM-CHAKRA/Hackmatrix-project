import { Navigate, Route, Routes } from 'react-router-dom';
import AppLayout from './layouts/AppLayout.jsx';
import HomePage from './pages/HomePage.jsx';
import ScannerPage from './pages/ScannerPage.jsx';
import ThreatFeedPage from './pages/ThreatFeedPage.jsx';
import CommunityPage from './pages/CommunityPage.jsx';
import VerifyPage from './pages/VerifyPage.jsx';
import LoginPage from './pages/LoginPage.jsx';
import RegisterPage from './pages/RegisterPage.jsx';
import ReportPage from './pages/ReportPage.jsx';
import NotFoundPage from './pages/NotFoundPage.jsx';

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/" element={<HomePage />} />
        <Route path="/scanner" element={<ScannerPage />} />
        <Route path="/threat-feed" element={<ThreatFeedPage />} />
        <Route path="/community" element={<CommunityPage />} />
        <Route path="/verify" element={<VerifyPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/report/:id" element={<ReportPage />} />
        {/* Old link kept working: the registry now lives in the Threat Feed. */}
        <Route path="/registry" element={<Navigate to="/threat-feed" replace />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
