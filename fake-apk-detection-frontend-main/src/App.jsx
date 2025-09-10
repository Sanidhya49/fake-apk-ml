import React, { useEffect } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { Toaster, toast } from "react-hot-toast";
import { HiExclamation, HiDocument } from "react-icons/hi";
import useAppStore from "./store/useAppStore";

// Layout Components
import Header from "./components/layout/Header";
import Footer from "./components/layout/Footer";

// Section Components
import HeroSection from "./components/sections/HeroSection";
import StatisticsSection from "./components/sections/StatisticsSection";
import ThreatFeedSection from "./components/sections/ThreatFeedSection";
import BatchUploadSection from "./components/sections/BatchUploadSection";
import NewsSection from "./components/sections/NewsSection";
import AnalysisSection from "./components/sections/AnalysisSection";
import NewResultsSection from "./components/sections/NewResultsSection";
import FAQSection from "./components/sections/FAQSection";
import AboutSection from "./components/sections/AboutSection";
import VideoDemoSection from "./components/sections/VideoDemoSection";

// Admin Components
import AdminLogin from "./pages/admin/AdminLogin";
import AdminDashboard from "./pages/admin/AdminDashboard";

// Main App Component (Homepage)
const MainApp = () => {
  const {
    analysisResults,
    isAnalyzing,
    reportError,
    setReportError,
    batchReportError,
    setBatchReportError,
  } = useAppStore();

  // Force dark mode always
  useEffect(() => {
    document.documentElement.classList.add("dark");
  }, []);

  // Show report error notifications
  useEffect(() => {
    if (reportError) {
      toast.error(reportError, {
        icon: <HiDocument className="w-5 h-5 text-danger-500" />,
        duration: 5000,
      });
      // Clear the error after showing it
      setReportError(null);
    }
  }, [reportError, setReportError]);

  // Show batch report error notifications
  useEffect(() => {
    if (batchReportError) {
      toast.error(batchReportError, {
        icon: <HiDocument className="w-5 h-5 text-danger-500" />,
        duration: 5000,
      });
      // Clear the error after showing it
      setBatchReportError(null);
    }
  }, [batchReportError, setBatchReportError]);

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      {/* Toast Notifications */}
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: "#1e293b",
            color: "#f8fafc",
            border: "1px solid #334155",
            borderRadius: "12px",
            padding: "16px",
            fontSize: "14px",
            fontWeight: "500",
          },
          success: {
            iconTheme: {
              primary: "#16a34a",
              secondary: "#1e293b",
            },
          },
          error: {
            iconTheme: {
              primary: "#dc2626",
              secondary: "#1e293b",
            },
          },
        }}
      />

      {/* Header */}
      <Header />

      {/* Main Content */}
      <main className="pt-16 md:pt-5">
        {/* Always show Hero and Stats sections */}
        <HeroSection />
        {/* Conditional Sections based on analysis state */}
        {!isAnalyzing && !analysisResults && (
          <>
            <BatchUploadSection />
            <ThreatFeedSection />
            <NewsSection />
          </>
        )}
        {isAnalyzing && <AnalysisSection />}
        {analysisResults && <NewResultsSection />}
        <VideoDemoSection />
        <AboutSection />
      </main>

      {/* Footer */}
      <Footer />
    </div>
  );
};

// Main App with Routing
const App = () => {
  return (
    <Routes>
      <Route path="/" element={<MainApp />} />
      <Route path="/admin/login" element={<AdminLogin />} />
      <Route path="/admin/dashboard" element={<AdminDashboard />} />
      <Route path="/admin" element={<Navigate to="/admin/login" replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
};

export default App;
