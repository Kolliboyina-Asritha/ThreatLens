import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext.jsx';
import { Navbar } from './components/Navbar.jsx';
import { Footer } from './components/Footer.jsx';
import { ProtectedRoute } from './components/ProtectedRoute.jsx';
import { PublicRoute } from './components/PublicRoute.jsx';

import { LoginPage } from './pages/LoginPage.jsx';
import { RegisterPage } from './pages/RegisterPage.jsx';
import { ScannerPage } from './pages/ScannerPage.jsx';
import { HistoryPage } from './pages/HistoryPage.jsx';
import { ScanDetailsPage } from './pages/ScanDetailsPage.jsx';
import { ProtectionDashboardPage } from './pages/ProtectionDashboardPage.jsx';
import { NotFoundPage } from './pages/NotFoundPage.jsx';

export const App = () => {
  return (
    <AuthProvider>
      <Router>
        <div className="flex flex-col min-h-screen bg-cyber-dark text-slate-100">
          <Navbar />

          <main className="flex-grow">
            <Routes>
              {/* Public Routes (Redirect to /scanner if already authenticated) */}
              <Route element={<PublicRoute />}>
                <Route path="/login" element={<LoginPage />} />
                <Route path="/register" element={<RegisterPage />} />
              </Route>

              {/* Protected Routes (Require active authentication session) */}
              <Route element={<ProtectedRoute />}>
                <Route path="/scanner" element={<ScannerPage />} />
                <Route path="/history" element={<HistoryPage />} />
                <Route path="/scans/:id" element={<ScanDetailsPage />} />
                <Route path="/protection" element={<ProtectionDashboardPage />} />
              </Route>

              {/* Default Redirect */}
              <Route path="/" element={<Navigate to="/scanner" replace />} />

              {/* 404 Fallback */}
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </main>

          <Footer />
        </div>
      </Router>
    </AuthProvider>
  );
};

export default App;
