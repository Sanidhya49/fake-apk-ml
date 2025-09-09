import React from "react";
import {
  HiCheckCircle,
  HiXCircle,
  HiExclamation,
  HiShieldCheck,
  HiRefresh,
  HiDownload,
} from "react-icons/hi";
import {
  BsShieldFillCheck,
  BsShieldFillExclamation,
  BsShieldFillX,
} from "react-icons/bs";
import useAppStore from "../../store/useAppStore";

const ResultsSection = () => {
  const {
    analysisResults,
    uploadedFile,
    resetApp,
    generateHTMLReport,
    isGeneratingReport,
    reportError,
  } = useAppStore();

  const handleDownloadReport = async () => {
    const success = await generateHTMLReport();
    if (success) {
      // HTML report download triggered successfully
      console.log("HTML report downloaded successfully");
    }
  };

  if (!analysisResults) {
    return null;
  }

  const {
    verdict,
    riskScore,
    confidence,
    securityBreakdown,
    threatDetection,
    recommendations,
  } = analysisResults;

  const getVerdictConfig = () => {
    switch (verdict) {
      case "safe":
        return {
          icon: BsShieldFillCheck,
          title: "SAFE",
          subtitle: "Application appears legitimate",
          color: "success",
          bgColor: "from-success-500 to-success-600",
          textColor: "text-success-600",
          borderColor: "border-success-700/50",
          bgLight: "bg-success-900/20",
        };
      case "suspicious":
        return {
          icon: BsShieldFillExclamation,
          title: "SUSPICIOUS",
          subtitle: "Potential security concerns detected",
          color: "warning",
          bgColor: "from-warning-500 to-warning-600",
          textColor: "text-warning-600",
          borderColor: "border-warning-700/50",
          bgLight: "bg-warning-900/20",
        };
      case "dangerous":
        return {
          icon: BsShieldFillX,
          title: "DANGEROUS",
          subtitle: "High-risk application - DO NOT INSTALL",
          color: "danger",
          bgColor: "from-danger-500 to-danger-600",
          textColor: "text-danger-600",
          borderColor: "border-danger-700/50",
          bgLight: "bg-danger-900/20",
        };
      default:
        return {
          icon: BsShieldFillCheck,
          title: "ANALYSIS COMPLETE",
          subtitle: "Review results below",
          color: "primary",
          bgColor: "from-primary-500 to-primary-600",
          textColor: "text-primary-600",
          borderColor: "border-primary-700/50",
          bgLight: "bg-primary-900/20",
        };
    }
  };

  const verdictConfig = getVerdictConfig();

  const getScoreColor = (score) => {
    if (score >= 80) return "text-success-400";
    if (score >= 60) return "text-warning-400";
    if (score >= 40) return "text-warning-400";
    return "text-danger-400";
  };

  const getScoreBarColor = (score) => {
    if (score >= 80) return "from-success-500 to-success-600";
    if (score >= 60) return "from-warning-500 to-warning-600";
    if (score >= 40) return "from-warning-500 to-danger-500";
    return "from-danger-500 to-danger-600";
  };

  const securityTests = [
    {
      name: "Code Integrity",
      score: securityBreakdown.codeIntegrity,
      unit: "/100",
    },
    {
      name: "Permission Analysis",
      score: securityBreakdown.permissionAnalysis,
      unit: "/100",
    },
    {
      name: "Network Behavior",
      score: securityBreakdown.networkBehavior,
      unit: "/100",
    },
    {
      name: "Data Encryption",
      score: securityBreakdown.dataEncryption,
      unit: "/100",
    },
  ];

  return (
    <section
      id="results"
      className="py-16 md:py-24 bg-gray-800 relative overflow-hidden"
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

        {/* Main Verdict Card */}
        <div
          className="mb-12 animate-fade-up"
          style={{ animationDelay: "200ms" }}
        >
          <div
            className={`p-8 md:p-12 rounded-2xl border-2 ${verdictConfig.borderColor} ${verdictConfig.bgLight} text-center relative overflow-hidden`}
          >
            {/* Background Glow */}
            <div
              className={`absolute inset-0 bg-gradient-to-r ${verdictConfig.bgColor} opacity-5 rounded-2xl`}
            ></div>

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

              {/* Risk Score Gauge */}
              <div className="max-w-md mx-auto mb-8">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-400">
                    Risk Score
                  </span>
                  <span
                    className={`text-2xl font-bold ${getScoreColor(
                      100 - riskScore
                    )}`}
                  >
                    {100 - riskScore}/100
                  </span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-4 overflow-hidden shadow-inner">
                  <div
                    className={`h-full bg-gradient-to-r ${getScoreBarColor(
                      100 - riskScore
                    )} rounded-full transition-all duration-1000`}
                    style={{ width: `${100 - riskScore}%` }}
                  />
                </div>
                <div className="flex justify-between text-xs text-gray-400 mt-1">
                  <span>High Risk</span>
                  <span>Low Risk</span>
                </div>
              </div>

              <div className="flex items-center justify-center space-x-8 text-sm text-gray-400">
                <div className="flex items-center">
                  <HiShieldCheck className="w-4 h-4 mr-2" />
                  Confidence: {confidence}%
                </div>
                <div className="flex items-center">
                  <HiCheckCircle className="w-4 h-4 mr-2" />
                  Analysis Complete
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Detailed Results Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
          {/* Security Breakdown */}
          <div className="animate-fade-up" style={{ animationDelay: "400ms" }}>
            <div className="h-full p-6 md:p-8 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
              <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                <HiShieldCheck className="w-6 h-6 text-primary-400 mr-3" />
                Security Breakdown
              </h3>

              <div className="space-y-6">
                {securityTests.map((test, index) => (
                  <div key={index}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-white">
                        {test.name}
                      </span>
                      <span
                        className={`font-bold ${getScoreColor(test.score)}`}
                      >
                        {test.score}
                        {test.unit}
                      </span>
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-3 overflow-hidden">
                      <div
                        className={`h-full bg-gradient-to-r ${getScoreBarColor(
                          test.score
                        )} rounded-full transition-all duration-1000`}
                        style={{
                          width: `${test.score}%`,
                          animationDelay: `${index * 200}ms`,
                        }}
                      />
                    </div>
                  </div>
                ))}

                {/* Digital Signature */}
                <div className="pt-4 border-t border-gray-700">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-white">
                      Digital Signature
                    </span>
                    <div className="flex items-center">
                      {securityBreakdown.digitalSignature === "valid" ? (
                        <>
                          <HiCheckCircle className="w-5 h-5 text-success-500 mr-2" />
                          <span className="text-success-400 font-medium">
                            Valid
                          </span>
                        </>
                      ) : (
                        <>
                          <HiExclamation className="w-5 h-5 text-warning-500 mr-2" />
                          <span className="text-warning-400 font-medium">
                            Warning
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Threat Detection */}
          <div className="animate-fade-up" style={{ animationDelay: "600ms" }}>
            <div className="h-full p-6 md:p-8 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
              <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                <HiXCircle className="w-6 h-6 text-danger-400 mr-3" />
                Threat Detection
              </h3>

              <div className="space-y-6">
                <div className="flex items-center justify-between p-4 rounded-lg bg-gray-800/50">
                  <span className="font-medium text-white">
                    Malware Signatures
                  </span>
                  <div className="flex items-center">
                    {threatDetection.malwareSignatures === 0 ? (
                      <>
                        <HiCheckCircle className="w-5 h-5 text-success-500 mr-2" />
                        <span className="text-success-400 font-bold">
                          0 Found
                        </span>
                      </>
                    ) : (
                      <>
                        <HiExclamation className="w-5 h-5 text-danger-500 mr-2" />
                        <span className="text-danger-400 font-bold">
                          {threatDetection.malwareSignatures} Found
                        </span>
                      </>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between p-4 rounded-lg bg-gray-800/50">
                  <span className="font-medium text-white">
                    Suspicious Permissions
                  </span>
                  <div className="flex items-center">
                    {threatDetection.suspiciousPermissions <= 2 ? (
                      <>
                        <HiCheckCircle className="w-5 h-5 text-success-500 mr-2" />
                        <span className="text-success-400 font-bold">
                          {threatDetection.suspiciousPermissions} Found
                        </span>
                      </>
                    ) : (
                      <>
                        <HiExclamation className="w-5 h-5 text-warning-500 mr-2" />
                        <span className="text-warning-400 font-bold">
                          {threatDetection.suspiciousPermissions} Found
                        </span>
                      </>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between p-4 rounded-lg bg-gray-800/50">
                  <span className="font-medium text-white">Known Threats</span>
                  <div className="flex items-center">
                    <HiCheckCircle className="w-5 h-5 text-success-500 mr-2" />
                    <span className="text-success-400 font-bold capitalize">
                      {threatDetection.knownThreats}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between p-4 rounded-lg bg-gray-800/50">
                  <span className="font-medium text-white">
                    Behavioral Analysis
                  </span>
                  <div className="flex items-center">
                    <HiCheckCircle className="w-5 h-5 text-success-500 mr-2" />
                    <span className="text-success-400 font-bold capitalize">
                      {threatDetection.behavioralAnalysis}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Recommendations */}
        <div
          className="mb-12 animate-fade-up"
          style={{ animationDelay: "800ms" }}
        >
          <div className="p-6 md:p-8 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
            <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
              <HiShieldCheck className="w-6 h-6 text-primary-400 mr-3" />
              Security Recommendations
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {recommendations.map((recommendation, index) => (
                <div
                  key={index}
                  className="flex items-start space-x-3 p-4 rounded-lg bg-gray-800/50"
                >
                  <div className="flex-shrink-0 w-6 h-6 bg-primary-900/40 rounded-full flex items-center justify-center mt-0.5">
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

        {/* Action Buttons */}
        <div
          className="flex flex-col sm:flex-row items-center justify-center gap-4 animate-fade-up"
          style={{ animationDelay: "1000ms" }}
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
        </div>
      </div>
    </section>
  );
};

export default ResultsSection;
