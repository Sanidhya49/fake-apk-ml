import React, { useEffect, useState } from "react";
import {
  HiClock,
  HiCheckCircle,
  HiXCircle,
  HiExclamation,
  HiArrowLeft,
  HiArrowUp,
} from "react-icons/hi";
import {
  HiMagnifyingGlass,
  HiDocumentMagnifyingGlass,
  HiShieldCheck,
  HiCreditCard,
  HiLockClosed,
  HiChartBar,
  HiBolt,
} from "react-icons/hi2";
import { BsShieldFillCheck } from "react-icons/bs";
import useAppStore from "../../store/useAppStore";
import { scrollToSection, scrollToTop } from "../../utils/scrollUtils";

const AnalysisSection = () => {
  const {
    isAnalyzing,
    analysisProgress,
    currentTest,
    analysisTests,
    uploadedFile,
    resetApp,
  } = useAppStore();

  const [timeElapsed, setTimeElapsed] = useState(0);
  const [estimatedTime, setEstimatedTime] = useState(25);

  // Time tracking - only track when actually analyzing
  useEffect(() => {
    if (!isAnalyzing) {
      setTimeElapsed(0);
      setEstimatedTime(25);
      return;
    }

    const timer = setInterval(() => {
      setTimeElapsed((prev) => prev + 1);
      // Update estimated time based on progress
      if (analysisProgress > 0) {
        const estimated = Math.max(
          0,
          Math.round(
            ((100 - analysisProgress) / analysisProgress) * timeElapsed
          )
        );
        setEstimatedTime(estimated);
      } else {
        setEstimatedTime((prev) => Math.max(0, prev - 1));
      }
    }, 1000);

    return () => clearInterval(timer);
  }, [isAnalyzing, analysisProgress, timeElapsed]);

  const getStatusIcon = (status) => {
    switch (status) {
      case "completed":
        return <HiCheckCircle className="w-5 h-5 text-success-500" />;
      case "warning":
        return <HiExclamation className="w-5 h-5 text-warning-500" />;
      case "failed":
        return <HiXCircle className="w-5 h-5 text-danger-500" />;
      case "running":
        return (
          <div className="w-5 h-5 border-2 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
        );
      default:
        return <HiClock className="w-5 h-5 text-gray-400" />;
    }
  };

  const getTestIcon = (iconName, status) => {
    const iconProps = {
      className: `w-6 h-6 transition-colors duration-300 ${
        status === "completed"
          ? "text-success-600 dark:text-success-400"
          : status === "warning"
          ? "text-warning-600 dark:text-warning-400"
          : status === "failed"
          ? "text-danger-600 dark:text-danger-400"
          : status === "running"
          ? "text-primary-400 animate-pulse"
          : "text-gray-500 dark:text-gray-400"
      }`,
    };

    const IconComponents = {
      HiDocumentMagnifyingGlass,
      HiMagnifyingGlass,
      HiShieldCheck,
      HiCreditCard,
      HiLockClosed,
      HiChartBar,
      HiBolt,
    };

    const IconComponent = IconComponents[iconName];
    return IconComponent ? (
      <IconComponent {...iconProps} />
    ) : (
      <HiClock {...iconProps} />
    );
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "completed":
        return "border-success-200 dark:border-success-700/50 bg-success-50 dark:bg-success-900/20";
      case "warning":
        return "border-warning-200 dark:border-warning-700/50 bg-warning-50 dark:bg-warning-900/20";
      case "failed":
        return "border-danger-200 dark:border-danger-700/50 bg-danger-50 dark:bg-danger-900/20";
      case "running":
        return "border-primary-200 dark:border-primary-700/50 bg-primary-50 dark:bg-primary-900/20 animate-pulse";
      default:
        return "border-gray-700/50 bg-white dark:bg-gray-800";
    }
  };

  if (!isAnalyzing) {
    return null;
  }

  return (
    <section
      id="analysis-section"
      className="py-16 md:py-24 bg-white dark:bg-gray-900 relative overflow-hidden"
    >
      {/* Background Effects */}
      <div className="absolute inset-0 opacity-2">
        <div className="absolute inset-0 bg-grid-pattern"></div>
      </div>

      {/* Animated Background Particles */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 left-10 w-2 h-2 bg-primary-400/30 rounded-full animate-float"></div>
        <div
          className="absolute top-32 right-20 w-3 h-3 bg-accent-400/30 rounded-full animate-float"
          style={{ animationDelay: "1s" }}
        ></div>
        <div
          className="absolute bottom-32 left-32 w-2 h-2 bg-teal-400/30 rounded-full animate-float"
          style={{ animationDelay: "2s" }}
        ></div>
      </div>

      <div className="relative z-10 max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-12 animate-fade-up">
          <div className="inline-flex items-center px-6 py-3 rounded-full bg-gradient-to-r from-primary-100 to-accent-100 dark:from-primary-900/30 dark:to-accent-900/30 border border-primary-200/50 dark:border-primary-700/50 mb-6">
            <BsShieldFillCheck className="w-5 h-5 text-primary-400 mr-2" />
            <span className="text-primary-700 dark:text-primary-300 font-medium">
              Security Analysis in Progress
            </span>
          </div>

          <h2 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4">
            Analyzing:{" "}
            <span className="text-primary-400">
              {uploadedFile?.name}
            </span>
          </h2>

          <div className="flex items-center justify-center space-x-8 text-sm text-gray-400">
            <div className="flex items-center">
              <HiClock className="w-4 h-4 mr-2" />
              Time Elapsed: {Math.floor(timeElapsed / 60)}:
              {(timeElapsed % 60).toString().padStart(2, "0")}
            </div>
            <div className="flex items-center">
              <BsShieldFillCheck className="w-4 h-4 mr-2" />
              ETA: {estimatedTime}s remaining
            </div>
            {/* WebSocket Status */}
            <div className="hidden md:block"></div>
          </div>
        </div>

        {/* Progress Overview */}
        <div
          className="mb-12 animate-fade-up"
          style={{ animationDelay: "200ms" }}
        >
          <div className="text-center mb-6">
            <div className="text-4xl md:text-5xl font-bold text-gray-900 dark:text-white mb-2">
              {Math.round(analysisProgress)}%
            </div>
            <p className="text-gray-400">
              Analysis Complete
            </p>
          </div>

          {/* Overall Progress Bar */}
          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3 overflow-hidden shadow-inner">
            <div
              className="h-full bg-gradient-to-r from-primary-500 to-teal-500 rounded-full transition-all duration-500 relative"
              style={{ width: `${Math.round(analysisProgress)}%` }}
            >
              {/* Scanning animation */}
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-scan"></div>
            </div>
          </div>
        </div>

        {/* Test Progress Grid */}
        <div
          className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-fade-up"
          style={{ animationDelay: "400ms" }}
        >
          {analysisTests.map((test) => (
            <div
              key={test.id}
              className={`p-6 rounded-xl border-2 transition-all duration-500 ${getStatusColor(
                test.status
              )}`}
            >
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <div className="relative">
                    {getTestIcon(test.icon, test.status)}
                    {test.status === "running" && (
                      <div className="absolute -inset-1 bg-primary-400/20 rounded-full animate-ping"></div>
                    )}
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-900 dark:text-white">
                      {test.name}
                    </h3>
                    <p className="text-sm text-gray-400 capitalize flex items-center">
                      {test.status === "running" ? (
                        <>
                          <span className="inline-flex items-center">
                            <span className="w-2 h-2 bg-primary-500 rounded-full animate-pulse mr-2"></span>
                            In Progress ({Math.round(test.progress)}%)
                          </span>
                        </>
                      ) : test.status === "completed" ? (
                        "Completed"
                      ) : test.status === "warning" ? (
                        "Warning"
                      ) : test.status === "failed" ? (
                        "Failed"
                      ) : (
                        "Pending"
                      )}
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  {test.status === "running" && (
                    <div className="text-sm text-primary-400 font-medium">
                      {Math.round(test.progress)}%
                    </div>
                  )}
                  {getStatusIcon(test.status)}
                </div>
              </div>

              {/* Individual Progress Bar */}
              <div className="w-full bg-gray-200/50 dark:bg-gray-600/50 rounded-full h-2 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-300 relative ${
                    test.status === "completed"
                      ? "bg-success-500"
                      : test.status === "warning"
                      ? "bg-warning-500"
                      : test.status === "failed"
                      ? "bg-danger-500"
                      : test.status === "running"
                      ? "bg-gradient-to-r from-primary-500 to-accent-500"
                      : "bg-gray-300 dark:bg-gray-600"
                  }`}
                  style={{ width: `${Math.round(test.progress)}%` }}
                >
                  {test.status === "running" && (
                    <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-scan"></div>
                  )}
                </div>
              </div>

              {/* Test Details */}
              {test.status === "running" && currentTest === test.id && (
                <div className="mt-3 p-3 rounded-lg bg-primary-50 dark:bg-primary-900/20 border border-primary-200 dark:border-primary-700/50">
                  <div className="flex items-center space-x-2 text-sm text-primary-700 dark:text-primary-300">
                    <div className="w-2 h-2 bg-primary-500 rounded-full animate-pulse"></div>
                    <span className="font-medium">Active Scan</span>
                  </div>
                  <p className="text-xs text-primary-400 mt-1">
                    {test.id === 1 &&
                      "Extracting and analyzing APK structure..."}
                    {test.id === 2 && "Deep scanning for malicious patterns..."}
                    {test.id === 3 &&
                      "Validating certificates and signatures..."}
                    {test.id === 4 && "Checking banking security protocols..."}
                    {test.id === 5 && "Testing encryption implementation..."}
                    {test.id === 6 && "Processing with ML algorithms..."}
                    {test.id === 7 && "Calculating final risk assessment..."}
                  </p>
                </div>
              )}

              {/* Completed Test Summary */}
              {test.status === "completed" && (
                <div className="mt-3 p-3 rounded-lg bg-success-50 dark:bg-success-900/20 border border-success-200 dark:border-success-700/50">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-success-700 dark:text-success-300 font-medium">
                      Scan Complete
                    </span>
                    <span className="text-xs text-success-600 dark:text-success-400 flex items-center">
                      <HiCheckCircle className="w-3 h-3 mr-1" />
                      Completed Successfully
                    </span>
                  </div>
                </div>
              )}

              {/* Warning State */}
              {test.status === "warning" && (
                <div className="mt-3 p-3 rounded-lg bg-warning-50 dark:bg-warning-900/20 border border-warning-200 dark:border-warning-700/50">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-warning-700 dark:text-warning-300 font-medium">
                      Minor Issues Found
                    </span>
                    <span className="text-xs text-warning-600 dark:text-warning-400 flex items-center">
                      <HiExclamation className="w-3 h-3 mr-1" />
                      Review required
                    </span>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Current Activity */}
        <div
          className="mt-12 text-center animate-fade-up"
          style={{ animationDelay: "600ms" }}
        >
          <div className="inline-flex items-center px-8 py-4 rounded-full bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border border-gray-700/50 shadow-lg">
            <div className="w-3 h-3 bg-gradient-to-r from-primary-500 to-accent-500 rounded-full animate-pulse mr-3"></div>
            <span className="text-gray-700 dark:text-gray-300 font-medium">
              {currentTest
                ? `${analysisTests.find((t) => t.id === currentTest)?.name}...`
                : "Initializing security analysis..."}
            </span>
          </div>
        </div>

        {/* Security Notice */}
        <div
          className="mt-12 p-6 rounded-xl bg-gradient-to-r from-teal-50 to-primary-50 dark:from-teal-900/20 dark:to-primary-900/20 border border-teal-200/50 dark:border-teal-700/50 animate-fade-up"
          style={{ animationDelay: "800ms" }}
        >
          <div className="flex items-center justify-center mb-4">
            <BsShieldFillCheck className="w-8 h-8 text-teal-600 dark:text-teal-400" />
          </div>
          <h3 className="text-xl font-semibold text-center text-gray-900 dark:text-white mb-2">
            Your Privacy is Protected
          </h3>
          <p className="text-center text-gray-400">
            This analysis is performed locally and securely. No sensitive data
            is stored or transmitted to external servers.
          </p>
        </div>

        {/* Floating Navigation */}
        <div className="fixed right-6 bottom-6 z-20 flex flex-col gap-3">
          {/* Cancel Analysis Button */}
          <button
            onClick={resetApp}
            className="p-3 bg-gray-600 hover:bg-gray-700 text-white rounded-full shadow-lg hover:shadow-xl transform hover:-translate-y-1 transition-all duration-300"
            title="Cancel Analysis & Go Back"
          >
            <HiArrowLeft className="w-5 h-5" />
          </button>

          {/* Scroll to Top Button */}
          <button
            onClick={scrollToTop}
            className="p-3 bg-primary-600 hover:bg-primary-700 text-white rounded-full shadow-lg hover:shadow-xl transform hover:-translate-y-1 transition-all duration-300"
            title="Scroll to Top"
          >
            <HiArrowUp className="w-5 h-5" />
          </button>
        </div>
      </div>
    </section>
  );
};

export default AnalysisSection;

