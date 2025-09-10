import React, { useState } from "react";
import {
  HiCheckCircle,
  HiXCircle,
  HiExclamation,
  HiShieldCheck,
  HiRefresh,
  HiDownload,
  HiClock,
  HiGlobe,
  HiCog,
  HiCode,
  HiCreditCard,
  HiArrowUp,
  HiChartBar,
  HiShieldExclamation,
} from "react-icons/hi";
import { HiExclamationTriangle } from "react-icons/hi2";
import {
  BsShieldFillCheck,
  BsShieldFillExclamation,
  BsShieldFillX,
} from "react-icons/bs";
import { marked } from "marked";
import useAppStore from "../../store/useAppStore";
import { scrollToSection, scrollToTop } from "../../utils/scrollUtils";
import AbuseReportModal from "./AbuseReportModal";

const NewResultsSection = () => {
  const {
    analysisResults,
    uploadedFile,
    resetApp,
    generateHTMLReport,
    isGeneratingReport,
  } = useAppStore();

  const [isAbuseReportModalOpen, setIsAbuseReportModalOpen] = useState(false);

  const handleDownloadReport = async () => {
    const success = await generateHTMLReport();
    if (success) {
      console.log("HTML report downloaded successfully");
    }
  };

  const handleReportAbuse = () => {
    setIsAbuseReportModalOpen(true);
  };

  const handleCloseAbuseReport = () => {
    setIsAbuseReportModalOpen(false);
  };

  if (!analysisResults) {
    return null;
  }

  const {
    prediction,
    probability,
    risk,
    riskColor,
    riskLevel,
    featureVector,
    recommendations,
    warnings,
    permissions_analysis,
    suspicious_apis_analysis,
    security_indicators,
    risk_factors,
    ai_explanation,
    performance_metrics,
    top_shap,
    batch_summary,
  } = analysisResults;

  const getVerdictConfig = () => {
    // Use the risk level from backend response for better accuracy
    const currentRiskColor =
      riskColor || (prediction === "fake" ? "danger" : "success");
    const currentRiskLevel =
      riskLevel || (prediction === "fake" ? "High Risk" : "Low Risk");

    switch (currentRiskColor) {
      case "success":
        return {
          icon: BsShieldFillCheck,
          title: "SAFE",
          subtitle: `${currentRiskLevel} - Application appears legitimate`,
          color: "success",
          bgColor: "from-success-500 to-success-600",
          textColor: "text-success-600",
          borderColor: "border-success-200 dark:border-success-700/50",
          bgLight: "bg-success-50 dark:bg-success-900/20",
        };
      case "warning":
        return {
          icon: BsShieldFillExclamation,
          title: "CAUTION",
          subtitle: `${currentRiskLevel} - Review carefully before installation`,
          color: "warning",
          bgColor: "from-warning-500 to-warning-600",
          textColor: "text-warning-600",
          borderColor: "border-warning-200 dark:border-warning-700/50",
          bgLight: "bg-warning-50 dark:bg-warning-900/20",
        };
      case "danger":
        return {
          icon: BsShieldFillX,
          title: "MALICIOUS",
          subtitle: `${currentRiskLevel} - DO NOT INSTALL`,
          color: "danger",
          bgColor: "from-danger-500 to-danger-600",
          textColor: "text-danger-600",
          borderColor: "border-danger-200 dark:border-danger-700/50",
          bgLight: "bg-danger-50 dark:bg-danger-900/20",
        };
      default:
        return {
          icon: BsShieldFillCheck,
          title: "ANALYSIS COMPLETE",
          subtitle: "Review results below",
          color: "primary",
          bgColor: "from-primary-500 to-primary-600",
          textColor: "text-primary-600",
          borderColor: "border-primary-200 dark:border-primary-700/50",
          bgLight: "bg-primary-50 dark:bg-primary-900/20",
        };
    }
  };

  const verdictConfig = getVerdictConfig();

  const getRiskBarColor = (currentRiskColor) => {
    switch (currentRiskColor) {
      case "success":
        return "from-success-500 to-success-600";
      case "warning":
        return "from-warning-500 to-warning-600";
      case "danger":
        return "from-danger-500 to-danger-600";
      default:
        return prediction === "fake"
          ? "from-danger-500 to-danger-600"
          : "from-success-500 to-success-600";
    }
  };

  const getRiskTextColor = (currentRiskColor) => {
    switch (currentRiskColor) {
      case "success":
        return "text-success-600 dark:text-success-400";
      case "warning":
        return "text-warning-600 dark:text-warning-400";
      case "danger":
        return "text-danger-600 dark:text-danger-400";
      default:
        return prediction === "fake"
          ? "text-danger-600 dark:text-danger-400"
          : "text-success-600 dark:text-success-400";
    }
  };

  const getWarningIcon = (iconName) => {
    switch (iconName) {
      case "HiExclamationTriangle":
        return HiExclamationTriangle;
      case "HiCode":
        return HiCode;
      case "HiCreditCard":
        return HiCreditCard;
      case "HiShieldExclamation":
        return HiExclamation;
      default:
        return HiExclamation;
    }
  };

  const getWarningColors = (type) => {
    switch (type) {
      case "critical":
        return {
          bg: "bg-danger-50 dark:bg-danger-900/20",
          border: "border-danger-200 dark:border-danger-700/50",
          text: "text-danger-700 dark:text-danger-300",
          icon: "text-danger-600 dark:text-danger-400",
        };
      case "high":
        return {
          bg: "bg-warning-50 dark:bg-warning-900/20",
          border: "border-warning-200 dark:border-warning-700/50",
          text: "text-warning-700 dark:text-warning-300",
          icon: "text-warning-600 dark:text-warning-400",
        };
      case "medium":
        return {
          bg: "bg-yellow-50 dark:bg-yellow-900/20",
          border: "border-yellow-200 dark:border-yellow-700/50",
          text: "text-yellow-700 dark:text-yellow-300",
          icon: "text-yellow-600 dark:text-yellow-400",
        };
      default:
        return {
          bg: "bg-gray-800/50",
          border: "border-gray-700/50",
          text: "text-gray-700 dark:text-gray-300",
          icon: "text-gray-400",
        };
    }
  };

  // Convert confidence percentage for display
  const calculateConfidence = (prediction, probability) => {
    if (prediction === "fake") {
      // For fake predictions, use probability directly (0.8 = 80% confidence)
      return Math.round((probability || 0) * 100);
    } else {
      // For legitimate predictions, use (1 - probability) to get confidence
      // If probability is 0.1 (10% chance of being fake), confidence is 90%
      return Math.round((1 - (probability || 0)) * 100);
    }
  };
  
  const confidenceScore = calculateConfidence(prediction, probability);

  return (
    <section
      id="results"
      className="py-16 md:py-24 bg-gray-900 relative overflow-hidden"
    >
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-2">
        <div className="absolute inset-0 bg-grid-pattern"></div>
      </div>

      <div className="relative z-10 max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-12 animate-fade-up">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Security Analysis
            <span className="block text-transparent bg-clip-text bg-gradient-to-r from-primary-400 to-teal-400">
              Complete
            </span>
          </h2>
          <p className="text-xl text-gray-300">
            Analysis results for:{" "}
            <span className="font-medium">{uploadedFile?.name}</span>
          </p>
        </div>

        {/* Threat Feed Match Indicator */}
        {analysisResults.threat_feed_match &&
          analysisResults.threat_feed_match.match && (
            <div
              id="threat-match"
              className="mb-8 animate-fade-up bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-700/30 rounded-2xl shadow-xl overflow-hidden"
              style={{ animationDelay: "150ms" }}
            >
              <div className="p-6">
                <div className="flex items-start">
                  <div className="flex-shrink-0">
                    <div className="w-12 h-12 bg-danger-500 rounded-full flex items-center justify-center">
                      <HiShieldExclamation className="w-6 h-6 text-white" />
                    </div>
                  </div>
                  <div className="ml-4 flex-1">
                    <h3 className="text-xl font-bold text-danger-800 dark:text-danger-300 mb-2">
                      🚨 KNOWN MALICIOUS APK DETECTED!
                    </h3>
                    <p className="text-danger-700 dark:text-danger-400 mb-4">
                      This APK matches a known bad indicator in our threat
                      intelligence feed.
                    </p>
                    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-danger-200 dark:border-danger-700/30">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                        <div>
                          <span className="font-semibold text-gray-700 dark:text-gray-300">
                            Match Type:
                          </span>
                          <span className="ml-2 text-danger-600 dark:text-danger-400 font-medium">
                            {analysisResults.threat_feed_match.type}
                          </span>
                        </div>
                        <div>
                          <span className="font-semibold text-gray-700 dark:text-gray-300">
                            Indicator:
                          </span>
                          <code className="ml-2 text-xs bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded text-danger-600 dark:text-danger-400">
                            {analysisResults.threat_feed_match.value}
                          </code>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

        {/* Main Verdict Card */}
        <div
          id="verdict-card"
          className="mb-12 animate-fade-up"
          style={{ animationDelay: "200ms" }}
        >
          <div
            className={`p-8 md:p-12 rounded-2xl border-2 ${verdictConfig.borderColor} ${verdictConfig.bgLight} text-center relative overflow-hidden`}
          >
            <div className="relative z-10">
              <verdictConfig.icon
                className={`w-20 h-20 mx-auto mb-6 ${verdictConfig.textColor}`}
              />

              <h3
                className={`text-4xl md:text-5xl font-bold mb-2 ${verdictConfig.textColor}`}
              >
                {verdictConfig.title}
              </h3>

              <p className="text-xl text-gray-400 mb-8">
                {verdictConfig.subtitle}
              </p>

              {/* Risk Score */}
              <div className="max-w-md mx-auto mb-8">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-400">
                    Risk Level: {riskLevel || "Unknown"}
                  </span>
                  <span
                    className={`text-2xl font-bold ${getRiskTextColor(
                      riskColor
                    )}`}
                  >
                    {confidenceScore}% Confidence
                  </span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-4 overflow-hidden shadow-inner">
                  <div
                    className={`h-full bg-gradient-to-r ${getRiskBarColor(
                      riskColor
                    )} rounded-full transition-all duration-1000`}
                    style={{ width: `${confidenceScore}%` }}
                  />
                </div>
              </div>

              <div className="flex items-center justify-center space-x-8 text-sm text-gray-400">
                <div className="flex items-center">
                  <HiShieldCheck className="w-4 h-4 mr-2" />
                  Prediction: {prediction || "Unknown"}
                </div>
                <div className="flex items-center">
                  <HiCheckCircle className="w-4 h-4 mr-2" />
                  Analysis Complete
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div
          className="flex flex-col sm:flex-row items-center justify-center gap-4 animate-fade-up mb-8"
          style={{ animationDelay: "1200ms" }}
        >
          <button
            onClick={resetApp}
            className="inline-flex items-center px-8 py-4 bg-gradient-to-r from-primary-600 to-teal-600 hover:from-primary-700 hover:to-teal-700 text-white font-semibold rounded-xl shadow-lg hover:shadow-xl transform hover:-translate-y-1 transition-all duration-300"
          >
            <HiRefresh className="w-5 h-5 mr-2" />
            Analyze Another APK
          </button>

          <button
            onClick={handleDownloadReport}
            disabled={isGeneratingReport}
            className="inline-flex items-center px-8 py-4 bg-white dark:bg-gray-800 border border-gray-700 text-gray-700 dark:text-gray-300 font-semibold rounded-xl hover:bg-gray-50 dark:hover:bg-gray-700 shadow-lg hover:shadow-xl transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isGeneratingReport ? (
              <>
                <div className="w-5 h-5 mr-2 animate-spin border-2 border-gray-400 border-t-gray-700 rounded-full" />
                Generating Report...
              </>
            ) : (
              <>
                <HiDownload className="w-5 h-5 mr-2" />
                Download Detailed Report
              </>
            )}
          </button>

          {/* Report Abuse Button - Show for high-risk APKs */}
          {(prediction === "fake" ||
            (probability && probability > 0.7) ||
            (analysisResults.threat_feed_match &&
              analysisResults.threat_feed_match.match)) && (
            <button
              onClick={handleReportAbuse}
              className="inline-flex items-center px-8 py-4 bg-gradient-to-r from-danger-600 to-danger-700 hover:from-danger-700 hover:to-danger-800 text-white font-semibold rounded-xl shadow-lg hover:shadow-xl transform hover:-translate-y-1 transition-all duration-300"
            >
              <HiShieldExclamation className="w-5 h-5 mr-2" />
              🚨 Report This APK
            </button>
          )}
        </div>

        {/* Warnings Section */}
        {warnings && warnings.length > 0 && (
          <div
            id="warnings-section"
            className="mb-12 animate-fade-up"
            style={{ animationDelay: "300ms" }}
          >
            <div className="space-y-4">
              <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                <HiExclamationTriangle className="w-6 h-6 text-warning-600 dark:text-warning-400 mr-3" />
                Security Warnings
              </h3>

              {warnings.map((warning, index) => {
                const WarningIcon = getWarningIcon(warning.icon);
                const colors = getWarningColors(warning.type);

                return (
                  <div
                    key={index}
                    className={`p-4 rounded-lg ${colors.bg} border ${colors.border}`}
                  >
                    <div className="flex items-start space-x-3">
                      <WarningIcon
                        className={`w-6 h-6 ${colors.icon} flex-shrink-0 mt-0.5`}
                      />
                      <div>
                        <h4 className={`font-bold ${colors.text} mb-2`}>
                          {warning?.title || "Security Warning"}
                        </h4>
                        <p
                          className={`${colors.text
                            .replace("700", "600")
                            .replace("300", "400")}`}
                        >
                          {warning?.message || "No details available"}
                        </p>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Security Indicators */}
        {security_indicators && (
          <div
            id="security-indicators"
            className="mb-12 animate-fade-up"
            style={{ animationDelay: "1000ms" }}
          >
            <div className="p-6 md:p-8 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
              <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                <HiShieldCheck className="w-6 h-6 text-blue-600 dark:text-blue-400 mr-3" />
                Security Indicators
                <div className="ml-auto">
                  <span className="px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
                    ML Analysis
                  </span>
                </div>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(security_indicators).map(
                  ([key, value], idx) => {
                    const isBoolean = typeof value === "boolean";
                    const isGoodIndicator =
                      key.includes("certificate") ||
                      key.includes("signature") ||
                      key.includes("official");
                    const displayValue = isBoolean
                      ? value
                        ? "Yes"
                        : "No"
                      : value;
                    
                    // Enhanced color scheme for better visual consistency
                    const getColorScheme = (key, value, isBoolean) => {
                      if (isBoolean) {
                        if (value === isGoodIndicator) {
                          return {
                            bg: "bg-gray-800/50",
                            border: "border-green-500/30",
                            text: "text-green-400",
                            icon: "text-green-500"
                          };
                        } else {
                          return {
                            bg: "bg-gray-800/50",
                            border: "border-red-500/30", 
                            text: "text-red-400",
                            icon: "text-red-500"
                          };
                        }
                      } else {
                        return {
                          bg: "bg-gray-800/50",
                          border: "border-gray-600/30",
                          text: "text-gray-300",
                          icon: "text-gray-500"
                        };
                      }
                    };

                    const colors = getColorScheme(key, value, isBoolean);

                    return (
                      <div
                        key={idx}
                        className={`p-4 rounded-lg ${colors.bg} border ${colors.border}`}
                      >
                        <div className="flex items-center mb-2">
                          <div className={`w-2 h-2 rounded-full ${colors.icon.replace('text-', 'bg-').replace('/500', '/500')} mr-2`}></div>
                          <div className="text-sm font-medium text-gray-400">
                            {key
                              .replace(/_/g, " ")
                              .replace(/\b\w/g, (l) => l.toUpperCase())}
                          </div>
                        </div>
                        <div className={`text-xl font-bold ${colors.text}`}>
                          {displayValue}
                        </div>
                      </div>
                    );
                  }
                )}
              </div>
            </div>
          </div>
        )}

        {/* Banking & Impersonation Analysis */}
        {(featureVector?.impersonation_score > 0 ||
          featureVector?.label_contains_bank === 1) && (
          <div
            className="mb-12 animate-fade-up"
            style={{ animationDelay: "1100ms" }}
          >
            <div className="p-6 md:p-8 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
              <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                <HiExclamation className="w-6 h-6 text-warning-600 dark:text-warning-400 mr-3" />
                Banking & Impersonation Analysis
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-lg bg-gray-800/50">
                  <div className="text-sm font-medium text-gray-400 mb-1">
                    Impersonation Score
                  </div>
                  <div
                    className={`text-2xl font-bold ${
                      (featureVector?.impersonation_score || 0) > 50
                        ? "text-danger-600 dark:text-danger-400"
                        : "text-success-600 dark:text-success-400"
                    }`}
                  >
                    {featureVector?.impersonation_score || 0}/100
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-gray-800/50">
                  <div className="text-sm font-medium text-gray-400 mb-1">
                    Banking Related
                  </div>
                  <div
                    className={`text-lg font-bold ${
                      featureVector?.label_contains_bank === 1 ||
                      featureVector?.package_contains_bank === 1
                        ? "text-warning-600 dark:text-warning-400"
                        : "text-success-600 dark:text-success-400"
                    }`}
                  >
                    {featureVector?.label_contains_bank === 1 ||
                    featureVector?.package_contains_bank === 1
                      ? "Yes"
                      : "No"}
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-gray-800/50">
                  <div className="text-sm font-medium text-gray-400 mb-1">
                    Package Length
                  </div>
                  <div className="text-lg font-bold text-gray-700 dark:text-gray-300">
                    {featureVector?.package_len || 0} chars
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* VirusTotal Analysis Results */}
        {analysisResults.virustotal_result && (
          <div
            id="virustotal-analysis"
            className="mb-12 animate-fade-up"
            style={{ animationDelay: "1000ms" }}
          >
            <div className="p-6 md:p-8 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
              <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                <HiShieldCheck className="w-6 h-6 text-green-600 dark:text-green-400 mr-3" />
                VirusTotal Analysis
                <div className="ml-auto">
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    analysisResults.virustotal_result.available 
                      ? 'bg-green-100 text-green-800' 
                      : 'bg-red-100 text-red-800'
                  }`}>
                    {analysisResults.virustotal_result.available ? 'Available' : 'Unavailable'}
                  </span>
                </div>
              </h3>
              
              {analysisResults.virustotal_result.available ? (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-gray-800/50 rounded-lg p-4 border border-red-500/30">
                      <div className="flex items-center mb-2">
                        <div className="w-2 h-2 rounded-full bg-red-500 mr-2"></div>
                        <div className="text-sm text-gray-400">Detection Engines</div>
                      </div>
                      <div className="text-3xl font-bold text-red-400">
                        {analysisResults.virustotal_result.last_analysis_stats?.malicious || 0}
                      </div>
                      <div className="text-sm text-red-300">Malicious</div>
                    </div>
                    <div className="bg-gray-800/50 rounded-lg p-4 border border-yellow-500/30">
                      <div className="flex items-center mb-2">
                        <div className="w-2 h-2 rounded-full bg-yellow-500 mr-2"></div>
                        <div className="text-sm text-gray-400">Suspicious</div>
                      </div>
                      <div className="text-3xl font-bold text-yellow-400">
                        {analysisResults.virustotal_result.last_analysis_stats?.suspicious || 0}
                      </div>
                      <div className="text-sm text-yellow-300">Suspicious</div>
                    </div>
                    <div className="bg-gray-800/50 rounded-lg p-4 border border-green-500/30">
                      <div className="flex items-center mb-2">
                        <div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div>
                        <div className="text-sm text-gray-400">Clean</div>
                      </div>
                      <div className="text-3xl font-bold text-green-400">
                        {analysisResults.virustotal_result.last_analysis_stats?.undetected || 0}
                      </div>
                      <div className="text-sm text-green-300">Undetected</div>
                    </div>
                  </div>
                  
                  <div className="bg-gray-800/50 rounded-lg p-4 border border-blue-500/30">
                    <div className="flex items-center mb-3">
                      <div className="w-2 h-2 rounded-full bg-blue-500 mr-2"></div>
                      <div className="text-sm text-gray-400">Analysis Summary</div>
                    </div>
                    <div className="text-white mb-3">
                      {analysisResults.virustotal_result.cached ? (
                        <div className="flex items-center">
                          <span className="text-blue-400 mr-2">📋</span>
                          <span>Cached result from VirusTotal database</span>
                        </div>
                      ) : (
                        <div className="flex items-center">
                          <span className="text-green-400 mr-2">🆕</span>
                          <span>Fresh scan completed</span>
                        </div>
                      )}
                    </div>
                    <div className="text-sm text-gray-300">
                      <span className="text-gray-400">SHA256:</span> 
                      <code className="bg-gray-700 px-2 py-1 rounded text-xs ml-2">
                        {analysisResults.virustotal_result.sha256?.substring(0, 16)}...
                      </code>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-gray-400 text-center py-8">
                  <HiExclamationTriangle className="w-12 h-12 mx-auto mb-4 text-yellow-500" />
                  <p className="text-lg mb-2">VirusTotal analysis unavailable</p>
                  <p className="text-sm">{analysisResults.virustotal_result.error || 'API key not configured'}</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* AI Explanation */}
        {ai_explanation && (
          <div
            id="ai-explanation"
            className="mb-12 animate-fade-up"
            style={{ animationDelay: "1200ms" }}
          >
            <div className="p-6 md:p-8 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
              <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                <HiCog className="w-6 h-6 text-teal-600 dark:text-teal-400 mr-3" />
                AI Security Analysis Explanation
              </h3>

              <div className="prose dark:prose-invert max-w-none">
                <div className="p-4 rounded-lg bg-gradient-to-r from-teal-50 to-blue-50 dark:from-teal-900/20 dark:to-blue-900/20 border border-teal-200 dark:border-teal-700/50">
                  <div className="flex items-start space-x-3">
                    <div className="flex-shrink-0 w-8 h-8 bg-teal-100 dark:bg-teal-900/40 rounded-full flex items-center justify-center mt-1">
                      <HiCog className="w-4 h-4 text-teal-600 dark:text-teal-400" />
                    </div>
                    <div className="flex-1">
                      <h4 className="text-lg font-semibold text-teal-900 dark:text-teal-100 mb-3">
                        Professional Security Assessment
                      </h4>
                      <div
                        className="text-teal-800 dark:text-teal-200 leading-relaxed markdown-content"
                        dangerouslySetInnerHTML={{
                          __html: ai_explanation
                            ? marked.parse(ai_explanation)
                            : "",
                        }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Risk Factors Analysis */}
        {risk_factors &&
          (risk_factors.high?.length > 0 ||
            risk_factors.medium?.length > 0 ||
            risk_factors.low?.length > 0 ||
            (risk_factors.overall_risk_score !== undefined &&
              risk_factors.overall_risk_score !== null)) && (
            <div
              className="mb-12 animate-fade-up"
              style={{ animationDelay: "1300ms" }}
            >
              <div className="p-6 md:p-8 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
                <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                  <HiExclamationTriangle className="w-6 h-6 text-warning-600 dark:text-warning-400 mr-3" />
                  Risk Factors Assessment
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* High Risk Factors */}
                  {risk_factors.high?.length > 0 && (
                    <div className="space-y-3">
                      <h4 className="text-lg font-semibold text-danger-700 dark:text-danger-300 flex items-center">
                        <HiXCircle className="w-5 h-5 mr-2" />
                        High Risk Factors ({risk_factors.high.length})
                      </h4>
                      <div className="space-y-3">
                        {risk_factors.high.map((factor, idx) => (
                          <div
                            key={idx}
                            className="p-3 rounded-lg bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-700/50"
                          >
                            <div className="font-medium text-danger-800 dark:text-danger-200 mb-1">
                              {factor?.factor || "Unknown Factor"}
                            </div>
                            <div className="text-sm text-danger-600 dark:text-danger-400">
                              {factor?.description ||
                                "No description available"}
                            </div>
                            {factor?.impact_score !== undefined &&
                              factor?.impact_score !== null && (
                                <div className="text-xs text-danger-500 dark:text-danger-500 mt-1">
                                  Impact Score: {factor.impact_score}/10
                                </div>
                              )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Medium Risk Factors */}
                  {risk_factors.medium?.length > 0 && (
                    <div className="space-y-3">
                      <h4 className="text-lg font-semibold text-warning-700 dark:text-warning-300 flex items-center">
                        <HiExclamationTriangle className="w-5 h-5 mr-2" />
                        Medium Risk Factors ({risk_factors.medium.length})
                      </h4>
                      <div className="space-y-3">
                        {risk_factors.medium.map((factor, idx) => (
                          <div
                            key={idx}
                            className="p-3 rounded-lg bg-warning-50 dark:bg-warning-900/20 border border-warning-200 dark:border-warning-700/50"
                          >
                            <div className="font-medium text-warning-800 dark:text-warning-200 mb-1">
                              {factor?.factor || "Unknown Factor"}
                            </div>
                            <div className="text-sm text-warning-600 dark:text-warning-400">
                              {factor?.description ||
                                "No description available"}
                            </div>
                            {factor?.impact_score !== undefined &&
                              factor?.impact_score !== null && (
                                <div className="text-xs text-warning-500 dark:text-warning-500 mt-1">
                                  Impact Score: {factor.impact_score}/10
                                </div>
                              )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Low Risk Factors */}
                  {risk_factors.low?.length > 0 && (
                    <div className="space-y-3 md:col-span-2">
                      <h4 className="text-lg font-semibold text-success-700 dark:text-success-300 flex items-center">
                        <HiCheckCircle className="w-5 h-5 mr-2" />
                        Low Risk Factors ({risk_factors.low.length})
                      </h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {risk_factors.low.map((factor, idx) => (
                          <div
                            key={idx}
                            className="p-3 rounded-lg bg-success-50 dark:bg-success-900/20 border border-success-200 dark:border-success-700/50"
                          >
                            <div className="font-medium text-success-800 dark:text-success-200 mb-1">
                              {factor?.factor || "Unknown Factor"}
                            </div>
                            <div className="text-sm text-success-600 dark:text-success-400">
                              {factor?.description ||
                                "No description available"}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Overall Risk Score */}
                  {risk_factors.overall_risk_score !== undefined &&
                    risk_factors.overall_risk_score !== null && (
                      <div className="md:col-span-2">
                        <div className="p-4 rounded-lg bg-gray-800/50">
                          <div className="flex justify-between items-center mb-2">
                            <span className="text-lg font-semibold text-white">
                              Overall Risk Score
                            </span>
                            <span
                              className={`text-2xl font-bold ${
                                risk_factors.overall_risk_score > 70
                                  ? "text-danger-600 dark:text-danger-400"
                                  : risk_factors.overall_risk_score > 40
                                  ? "text-warning-600 dark:text-warning-400"
                                  : "text-success-600 dark:text-success-400"
                              }`}
                            >
                              {typeof risk_factors.overall_risk_score ===
                              "number"
                                ? risk_factors.overall_risk_score
                                : 0}
                              /100
                            </span>
                          </div>
                          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-4">
                            <div
                              className={`h-4 rounded-full bg-gradient-to-r ${
                                risk_factors.overall_risk_score > 70
                                  ? "from-danger-500 to-danger-600"
                                  : risk_factors.overall_risk_score > 40
                                  ? "from-warning-500 to-warning-600"
                                  : "from-success-500 to-success-600"
                              }`}
                              style={{
                                width: `${
                                  typeof risk_factors.overall_risk_score ===
                                  "number"
                                    ? risk_factors.overall_risk_score
                                    : 0
                                }%`,
                              }}
                            />
                          </div>
                        </div>
                      </div>
                    )}
                </div>
              </div>
            </div>
          )}

        {/* SHAP Feature Importance */}
        {top_shap &&
          top_shap.length > 0 &&
          top_shap.some(
            (feature) => feature.feature_name && feature.shap_value != null
          ) && (
            <div
              className="mb-12 animate-fade-up"
              style={{ animationDelay: "1400ms" }}
            >
              <div className="p-6 md:p-8 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
                <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                  <HiChartBar className="w-6 h-6 text-blue-600 dark:text-blue-400 mr-3" />
                  AI Model Feature Analysis
                </h3>

                <div className="space-y-4">
                  <p className="text-gray-400 mb-6">
                    These features had the most influence on the AI model's
                    decision:
                  </p>

                  {top_shap
                    .filter(
                      (feature) =>
                        feature.feature_name && feature.shap_value != null
                    )
                    .map((feature, idx) => (
                      <div
                        key={idx}
                        className="p-4 rounded-lg bg-gray-800/50"
                      >
                        <div className="flex justify-between items-start mb-2">
                          <div className="flex-1">
                            <h4 className="font-semibold text-white">
                              {feature.feature_name || "Unknown Feature"}
                            </h4>
                            <p className="text-sm text-gray-400">
                              Value:{" "}
                              {feature.feature_value !== undefined &&
                              feature.feature_value !== null
                                ? feature.feature_value
                                : "N/A"}
                            </p>
                          </div>
                          <div className="text-right">
                            <div
                              className={`text-lg font-bold ${
                                (feature.shap_value || 0) > 0
                                  ? "text-danger-600 dark:text-danger-400"
                                  : "text-success-600 dark:text-success-400"
                              }`}
                            >
                              {(feature.shap_value || 0) > 0 ? "+" : ""}
                              {typeof feature.shap_value === "number"
                                ? feature.shap_value.toFixed(3)
                                : "0.000"}
                            </div>
                            <div className="text-xs text-gray-500 dark:text-gray-500">
                              {(feature.shap_value || 0) > 0
                                ? "Increases Risk"
                                : "Decreases Risk"}
                            </div>
                          </div>
                        </div>

                        {/* SHAP value bar */}
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className={`h-2 rounded-full ${
                              (feature.shap_value || 0) > 0
                                ? "bg-gradient-to-r from-danger-500 to-danger-600"
                                : "bg-gradient-to-r from-success-500 to-success-600"
                            }`}
                            style={{
                              width: `${Math.min(
                                Math.abs(feature.shap_value || 0) * 100,
                                100
                              )}%`,
                            }}
                          />
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          )}

        {/* Performance Metrics */}
        {performance_metrics &&
          (performance_metrics.analysis_time ||
            performance_metrics.file_size ||
            performance_metrics.features_extracted ||
            performance_metrics.model_confidence !== undefined) && (
            <div
              className="mb-12 animate-fade-up"
              style={{ animationDelay: "1500ms" }}
            >
              <div className="p-6 md:p-8 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
                <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                  <HiClock className="w-6 h-6 text-green-600 dark:text-green-400 mr-3" />
                  Analysis Performance
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  {performance_metrics.analysis_time && (
                    <div className="p-4 rounded-lg bg-gray-800/50 text-center">
                      <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                        {typeof performance_metrics.analysis_time === "number"
                          ? performance_metrics.analysis_time.toFixed(2)
                          : performance_metrics.analysis_time}
                        s
                      </div>
                      <div className="text-sm text-gray-400">
                        Analysis Time
                      </div>
                    </div>
                  )}

                  {performance_metrics.file_size && (
                    <div className="p-4 rounded-lg bg-gray-800/50 text-center">
                      <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                        {(typeof performance_metrics.file_size === "number"
                          ? performance_metrics.file_size / (1024 * 1024)
                          : 0
                        ).toFixed(1)}
                        MB
                      </div>
                      <div className="text-sm text-gray-400">
                        File Size
                      </div>
                    </div>
                  )}

                  {performance_metrics.features_extracted && (
                    <div className="p-4 rounded-lg bg-gray-800/50 text-center">
                      <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                        {performance_metrics.features_extracted}
                      </div>
                      <div className="text-sm text-gray-400">
                        Features Extracted
                      </div>
                    </div>
                  )}

                  {performance_metrics.model_confidence !== undefined &&
                    performance_metrics.model_confidence !== null && (
                      <div className="p-4 rounded-lg bg-gray-800/50 text-center">
                        <div className="text-2xl font-bold text-teal-600 dark:text-teal-400">
                          {(typeof performance_metrics.model_confidence ===
                          "number"
                            ? performance_metrics.model_confidence * 100
                            : 0
                          ).toFixed(1)}
                          %
                        </div>
                        <div className="text-sm text-gray-400">
                          Model Confidence
                        </div>
                      </div>
                    )}
                </div>
              </div>
            </div>
          )}

        {/* Batch Summary (for batch analysis) */}
        {batch_summary && (
          <div
            className="mb-12 animate-fade-up"
            style={{ animationDelay: "1600ms" }}
          >
            <div className="p-6 md:p-8 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
              <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                <HiCog className="w-6 h-6 text-indigo-600 dark:text-indigo-400 mr-3" />
                Batch Analysis Summary
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <div className="p-4 rounded-lg bg-gray-800/50 text-center">
                  <div className="text-2xl font-bold text-white">
                    {batch_summary?.total_files || 0}
                  </div>
                  <div className="text-sm text-gray-400">
                    Total Files
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-gray-800/50 text-center">
                  <div className="text-2xl font-bold text-danger-600 dark:text-danger-400">
                    {batch_summary?.malicious_count || 0}
                  </div>
                  <div className="text-sm text-gray-400">
                    Malicious
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-gray-800/50 text-center">
                  <div className="text-2xl font-bold text-success-600 dark:text-success-400">
                    {batch_summary?.safe_count || 0}
                  </div>
                  <div className="text-sm text-gray-400">
                    Safe
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-gray-800/50 text-center">
                  <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                    {batch_summary.average_confidence !== undefined &&
                    batch_summary.average_confidence !== null
                      ? typeof batch_summary.average_confidence === "number"
                        ? batch_summary.average_confidence.toFixed(1)
                        : "0.0"
                      : "0.0"}
                    %
                  </div>
                  <div className="text-sm text-gray-400">
                    Avg Confidence
                  </div>
                </div>
              </div>

              {batch_summary.high_risk_files &&
                batch_summary.high_risk_files.length > 0 && (
                  <div className="p-4 rounded-lg bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-700/50">
                    <h4 className="font-semibold text-danger-700 dark:text-danger-300 mb-3 flex items-center">
                      <HiXCircle className="w-4 h-4 mr-2" />
                      High Risk Files ({batch_summary.high_risk_files.length})
                    </h4>
                    <div className="space-y-2">
                      {batch_summary.high_risk_files
                        .slice(0, 5)
                        .map((file, idx) => (
                          <div
                            key={idx}
                            className="text-sm text-danger-600 dark:text-danger-400"
                          >
                            • {file}
                          </div>
                        ))}
                      {batch_summary.high_risk_files?.length > 5 && (
                        <div className="text-sm text-danger-500 dark:text-danger-500 italic">
                          ... and {batch_summary.high_risk_files.length - 5}{" "}
                          more high risk files
                        </div>
                      )}
                    </div>
                  </div>
                )}
            </div>
          </div>
        )}

        {/* Recommendations */}
        <div
          id="recommendations-section"
          className="mb-12 animate-fade-up"
          style={{ animationDelay: "1700ms" }}
        >
          <div className="p-6 md:p-8 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
            <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
              <HiShieldCheck className="w-6 h-6 text-primary-400 mr-3" />
              Security Recommendations
            </h3>

            <div className="space-y-4">
              {prediction === "fake" ? (
                <div className="p-4 rounded-lg bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-700/50">
                  <div className="flex items-start space-x-3">
                    <HiXCircle className="w-6 h-6 text-danger-600 dark:text-danger-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <h4 className="font-bold text-danger-700 dark:text-danger-300 mb-2">
                        HIGH RISK - DO NOT INSTALL
                      </h4>
                      <p className="text-danger-600 dark:text-danger-400">
                        This application has been identified as potentially
                        malicious. Installing it could compromise your device
                        security and personal data.
                      </p>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-success-50 dark:bg-success-900/20 border border-success-200 dark:border-success-700/50">
                  <div className="flex items-start space-x-3">
                    <HiCheckCircle className="w-6 h-6 text-success-600 dark:text-success-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <h4 className="font-bold text-success-700 dark:text-success-300 mb-2">
                        Application Appears Safe
                      </h4>
                      <p className="text-success-600 dark:text-success-400">
                        The analysis indicates this application is likely safe
                        to install, but always exercise caution with any APK
                        files.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {recommendations &&
                recommendations.map((recommendation, index) => (
                  <div
                    key={index}
                    className="flex items-start space-x-3 p-4 rounded-lg bg-gray-800/50"
                  >
                    <div className="flex-shrink-0 w-6 h-6 bg-primary-100 dark:bg-primary-900/40 rounded-full flex items-center justify-center mt-0.5">
                      <span className="text-primary-400 text-sm font-bold">
                        {index + 1}
                      </span>
                    </div>
                    <p className="text-gray-700 dark:text-gray-300">
                      {recommendation}
                    </p>
                  </div>
                ))}
            </div>
          </div>
        </div>

        {/* Floating Navigation & Scroll to Top */}
        <div className="fixed right-4 bottom-4 z-20 flex flex-col items-center gap-4">
          {/* Quick Navigation */}
          <div className="bg-gray-900/95 backdrop-blur-sm rounded-2xl shadow-2xl border border-gray-700/50 overflow-hidden max-h-96 overflow-y-auto">
            <div className="p-3">
              <div className="flex items-center mb-2">
                <HiCog className="w-3.5 h-3.5 text-teal-500 mr-2" />
                <p className="text-xs text-gray-300 font-semibold">
                  Quick Nav
                </p>
              </div>
              <div className="space-y-1">
                <button
                  onClick={() => scrollToSection("verdict-card", 100)}
                  className="w-full flex items-center px-2 py-2 text-xs text-gray-300 hover:bg-gray-800/50 hover:text-white rounded-lg transition-all duration-200 group"
                  title="View Security Verdict"
                >
                  <BsShieldFillCheck className="w-3 h-3 mr-2 text-green-500 group-hover:text-green-400 transition-colors flex-shrink-0" />
                  <span className="truncate">Verdict</span>
                </button>

                {warnings && warnings.length > 0 && (
                  <button
                    onClick={() => scrollToSection("warnings-section", 100)}
                    className="w-full flex items-center px-2 py-2 text-xs text-gray-300 hover:bg-gray-800/50 hover:text-white rounded-lg transition-all duration-200 group"
                    title="View Security Warnings"
                  >
                    <HiExclamationTriangle className="w-3 h-3 mr-2 text-yellow-500 group-hover:text-yellow-400 transition-colors flex-shrink-0" />
                    <span className="truncate">Warnings</span>
                  </button>
                )}

                {security_indicators && (
                  <button
                    onClick={() => scrollToSection("security-indicators", 100)}
                    className="w-full flex items-center px-2 py-2 text-xs text-gray-300 hover:bg-gray-800/50 hover:text-white rounded-lg transition-all duration-200 group"
                    title="View Security Indicators"
                  >
                    <HiShieldCheck className="w-3 h-3 mr-2 text-blue-500 group-hover:text-blue-400 transition-colors flex-shrink-0" />
                    <span className="truncate">Indicators</span>
                  </button>
                )}

                {analysisResults.virustotal_result && (
                  <button
                    onClick={() => scrollToSection("virustotal-analysis", 100)}
                    className="w-full flex items-center px-2 py-2 text-xs text-gray-300 hover:bg-gray-800/50 hover:text-white rounded-lg transition-all duration-200 group"
                    title="View VirusTotal Analysis"
                  >
                    <HiShieldCheck className="w-3 h-3 mr-2 text-green-500 group-hover:text-green-400 transition-colors flex-shrink-0" />
                    <span className="truncate">VirusTotal</span>
                  </button>
                )}

                {ai_explanation && (
                  <button
                    onClick={() => scrollToSection("ai-explanation", 100)}
                    className="w-full flex items-center px-2 py-2 text-xs text-gray-300 hover:bg-gray-800/50 hover:text-white rounded-lg transition-all duration-200 group"
                    title="View AI Analysis"
                  >
                    <HiCog className="w-3 h-3 mr-2 text-teal-500 group-hover:text-teal-400 transition-colors flex-shrink-0" />
                    <span className="truncate">AI Analysis</span>
                  </button>
                )}

                <button
                  onClick={() => scrollToSection("recommendations-section", 100)}
                  className="w-full flex items-center px-2 py-2 text-xs text-gray-300 hover:bg-gray-800/50 hover:text-white rounded-lg transition-all duration-200 group"
                  title="View Security Recommendations"
                >
                  <HiShieldCheck className="w-3 h-3 mr-2 text-purple-500 group-hover:text-purple-400 transition-colors flex-shrink-0" />
                  <span className="truncate">Recommendations</span>
                </button>
              </div>
            </div>
          </div>

          {/* Scroll to Top Button */}
          <button
            onClick={scrollToTop}
            className="w-10 h-10 bg-gray-800/80 hover:bg-gray-700/80 backdrop-blur-sm text-gray-300 hover:text-white rounded-full shadow-lg hover:shadow-xl transform hover:-translate-y-1 transition-all duration-300 group border border-gray-600/50 flex items-center justify-center"
            title="Scroll to Top"
          >
            <HiArrowUp className="w-4 h-4 group-hover:scale-110 transition-transform" />
          </button>
        </div>
      </div>

      {/* Abuse Report Modal */}
      <AbuseReportModal
        isOpen={isAbuseReportModalOpen}
        onClose={handleCloseAbuseReport}
        preFilledFile={uploadedFile?.file || uploadedFile}
      />
    </section>
  );
};

export default NewResultsSection;

