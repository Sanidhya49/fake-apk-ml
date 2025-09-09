import { create } from "zustand";
import { APKAnalysisService } from "../services/api";
import { scrollToSection } from "../utils/scrollUtils";

const useAppStore = create((set, get) => ({
  // Theme state - Always dark mode
  isDarkMode: true,

  // Navigation state
  isMobileMenuOpen: false,
  setMobileMenuOpen: (isOpen) => set({ isMobileMenuOpen: isOpen }),

  // File upload state
  uploadedFile: null,
  isUploading: false,
  uploadError: null,
  setUploadedFile: (file) => set({ uploadedFile: file, uploadError: null }),
  setUploading: (isUploading) => set({ isUploading }),
  setUploadError: (error) => set({ uploadError: error }),
  clearFile: () =>
    set({
      uploadedFile: null,
      uploadError: null,
      analysisResults: null,
      isAnalyzing: false,
    }),

  // Analysis state - simplified to just isAnalyzing flag
  isAnalyzing: false,

  // Progress tracking for analysis section
  analysisProgress: 0,
  currentTest: null,
  analysisTests: [
    {
      id: 1,
      name: "APK Structure Analysis",
      icon: "HiDocumentMagnifyingGlass",
      status: "pending",
      progress: 0,
    },
    {
      id: 2,
      name: "Malware Detection",
      icon: "HiMagnifyingGlass",
      status: "pending",
      progress: 0,
    },
    {
      id: 3,
      name: "Certificate Validation",
      icon: "HiShieldCheck",
      status: "pending",
      progress: 0,
    },
    {
      id: 4,
      name: "Banking Security Check",
      icon: "HiCreditCard",
      status: "pending",
      progress: 0,
    },
    {
      id: 5,
      name: "Encryption Analysis",
      icon: "HiLockClosed",
      status: "pending",
      progress: 0,
    },
    {
      id: 6,
      name: "Machine Learning Analysis",
      icon: "HiChartBar",
      status: "pending",
      progress: 0,
    },
    {
      id: 7,
      name: "Risk Assessment",
      icon: "HiBolt",
      status: "pending",
      progress: 0,
    },
  ],

  // Analysis results state
  analysisResults: null,
  setAnalysisResults: (results) => set({ analysisResults: results }),

  // Statistics (for demo)
  statistics: {
    apksAnalyzed: "10,000+",
    accuracyRate: "99.7%",
    realTimeDetection: "Active",
    dataStored: "Zero",
  },

  // App flow state - removed currentView since we'll handle this with simple conditional rendering
  // Based on isAnalyzing and analysisResults states

  // Start analysis flow - simplified to just send request and wait for response
  startAnalysis: async () => {
    const state = get();
    if (!state.uploadedFile) return;

    console.log("Starting analysis for file:", state.uploadedFile.name);
    console.log(
      "API Base URL:",
      import.meta.env.VITE_API_BASE_URL || "http://localhost:9000"
    );

    // Reset analysis state
    set({
      isAnalyzing: true,
      analysisResults: null,
      uploadError: null,
      analysisProgress: 0,
      currentTest: 1,
      analysisTests: state.analysisTests.map((test) => ({
        ...test,
        status: "pending",
        progress: 0,
      })),
    });

    // Scroll to analysis section with a slight delay to ensure DOM is updated
    setTimeout(() => {
      scrollToSection("analysis-section", 100);
    }, 100);

    try {
      // Start progress simulation while API call is happening
      const progressInterval = state.simulateAnalysisProgress();

      // Perform API call
      console.log("Making API call to scan endpoint...");
      const response = await APKAnalysisService.scanSingle(
        state.uploadedFile.file || state.uploadedFile
      );

      console.log("API response received:", response.data);

      // Clear the progress simulation
      clearInterval(progressInterval);

      // Process the response data to match expected frontend format
      const result = response.data;

      // Map risk level to consistent format
      const getRiskColor = (risk) => {
        switch (risk?.toLowerCase()) {
          case "red":
            return "danger";
          case "yellow":
            return "warning";
          case "green":
            return "success";
          default:
            return result.prediction === "fake" ? "danger" : "success";
        }
      };

      const getRiskLevel = (risk) => {
        switch (risk?.toLowerCase()) {
          case "red":
            return "High Risk";
          case "yellow":
            return "Medium Risk";
          case "green":
            return "Low Risk";
          default:
            return result.prediction === "fake" ? "High Risk" : "Low Risk";
        }
      };

      const processedResults = {
        prediction: result.prediction,
        probability: result.probability,
        risk: result.risk,
        riskColor: getRiskColor(result.risk),
        riskLevel: getRiskLevel(result.risk),
        riskScore: Math.round((result.probability || 0) * 100),
        verdict: result.prediction === "fake" ? "dangerous" : "safe",
        confidence: Math.round((result.probability || 0) * 100),

        // Enhanced API response fields
        permissions_analysis: result.permissions_analysis,
        suspicious_apis_analysis: result.suspicious_apis_analysis,
        security_indicators: result.security_indicators,
        risk_factors: result.risk_factors,
        ai_explanation: result.ai_explanation,
        performance_metrics: result.performance_metrics,
        top_shap: result.top_shap,
        batch_summary: result.batch_summary, // For batch processing

        // Map backend features to frontend display format
        summary: {
          fileName: state.uploadedFile.name,
          fileSize: state.uploadedFile.size,
          scanTime: new Date().toISOString(),
          verdict:
            result.prediction === "fake"
              ? "Potentially Malicious"
              : "Appears Safe",
          riskLevel: getRiskLevel(result.risk),
          confidence: Math.round((result.probability || 0) * 100),
        },

        // Security breakdown based on feature vector
        securityBreakdown: {
          codeIntegrity: result.feature_vector?.cert_present ? 85 : 45,
          permissionAnalysis: Math.max(
            20,
            100 - (result.feature_vector?.num_permissions || 0) * 5
          ),
          networkBehavior:
            (result.feature_vector?.num_suspicious_tld || 0) === 0 ? 90 : 60,
          dataEncryption: result.feature_vector?.cert_present ? 80 : 40,
          digitalSignature:
            result.feature_vector?.cert_present === 1 ? "valid" : "warning",
        },

        // Threat detection details
        threatDetection: {
          malwareSignatures: result.feature_vector?.count_suspicious || 0,
          suspiciousPermissions: result.feature_vector?.num_permissions || 0,
          knownThreats: result.prediction === "fake" ? "detected" : "none",
          behavioralAnalysis:
            result.prediction === "fake" ? "suspicious" : "clean",
        },

        details: {
          // Security Analysis
          permissions: result.feature_vector?.num_permissions || 0,
          suspiciousAPIs: result.feature_vector?.count_suspicious || 0,
          certificateValid: result.feature_vector?.cert_present === 1,

          // Banking & Finance
          bankingRelated:
            result.feature_vector?.label_contains_bank === 1 ||
            result.feature_vector?.package_contains_bank === 1,
          impersonationScore: result.feature_vector?.impersonation_score || 0,
          officialPackage: result.feature_vector?.pkg_official === 1,

          // Technical Details
          minSDK: result.feature_vector?.min_sdk || 0,
          targetSDK: result.feature_vector?.target_sdk || 0,
          domains: result.feature_vector?.num_domains || 0,
          suspiciousDomains: result.feature_vector?.num_suspicious_tld || 0,
          activities: result.feature_vector?.num_activities || 0,
          services: result.feature_vector?.num_services || 0,
          receivers: result.feature_vector?.num_receivers || 0,
          dexFiles: result.feature_vector?.num_dex || 0,
        },

        // Generate recommendations based on analysis and risk level
        recommendations: (() => {
          const recs = [];

          if (result.prediction === "fake") {
            recs.push(
              "DO NOT INSTALL - This application has been identified as potentially malicious"
            );
            recs.push(
              "Installing this app may compromise your device security and personal data"
            );
          } else {
            recs.push("Application appears safe based on our analysis");
          }

          if (result.feature_vector?.impersonation_score > 50) {
            recs.push(
              `High impersonation risk score (${
                result.feature_vector.impersonation_score || 0
              }/100) - This app may be impersonating another application`
            );
          }

          if (result.feature_vector?.cert_present === 0) {
            recs.push(
              "No digital certificate found - Verify the application source before installation"
            );
          }

          if (result.feature_vector?.count_suspicious > 0) {
            recs.push(
              `${
                result.feature_vector.count_suspicious || 0
              } suspicious API calls detected`
            );
          }

          if (result.feature_vector?.num_suspicious_tld > 0) {
            recs.push(
              `${
                result.feature_vector.num_suspicious_tld || 0
              } suspicious network domains detected`
            );
          }

          if (result.feature_vector?.pkg_official === 0) {
            recs.push("Not from an official package source - Exercise caution");
          }

          // Always add general security recommendations
          recs.push(
            "Always download applications from official app stores when possible"
          );
          recs.push("Review app permissions carefully before installation");

          return recs;
        })(),

        // Include top SHAP features if available
        topFeatures: result.top_shap || [],
        // Raw feature vector for advanced users
        featureVector: result.feature_vector,

        // Add warnings based on analysis
        warnings: (() => {
          const warnings = [];

          if (result.prediction === "fake") {
            warnings.push({
              type: "critical",
              icon: "HiShieldExclamation",
              title: "Malicious Application Detected",
              message:
                "Our analysis indicates this APK contains malicious code. Do not install this application.",
            });
          }

          if (result.feature_vector?.impersonation_score > 70) {
            warnings.push({
              type: "high",
              icon: "HiExclamationTriangle",
              title: "High Impersonation Risk",
              message: `This app has a ${
                result.feature_vector.impersonation_score || 0
              }% impersonation score, suggesting it may be mimicking a legitimate application.`,
            });
          }

          if (result.feature_vector?.count_suspicious > 0) {
            warnings.push({
              type:
                (result.feature_vector.count_suspicious || 0) > 3
                  ? "high"
                  : "medium",
              icon: "HiCode",
              title: "Suspicious API Usage",
              message: `Found ${
                result.feature_vector.count_suspicious || 0
              } suspicious API calls that could be used for malicious purposes.`,
            });
          }

          if (
            result.feature_vector?.label_contains_bank === 1 ||
            result.feature_vector?.package_contains_bank === 1
          ) {
            warnings.push({
              type: "high",
              icon: "HiCreditCard",
              title: "Banking-Related Application",
              message:
                "This app appears to be banking-related. Only install if from your official bank and verify authenticity.",
            });
          }

          return warnings;
        })(),
      };

      state.completeAnalysis(processedResults);
    } catch (error) {
      console.error("Analysis failed:", error);

      let errorMessage = "Analysis failed";
      if (error.response?.status === 422) {
        errorMessage =
          "Could not parse APK file. Please ensure you uploaded a valid APK file.";
      } else if (error.response?.status >= 500) {
        errorMessage = "Server error during analysis. Please try again later.";
      } else if (error.code === "ECONNABORTED") {
        errorMessage =
          "Analysis timed out. The APK file may be too large or complex.";
      } else if (error.response?.data?.error) {
        errorMessage = `Analysis failed: ${error.response.data.error}`;
      } else if (error.message) {
        errorMessage = `Analysis failed: ${error.message}`;
      }

      set({
        uploadError: errorMessage,
        isAnalyzing: false,
        analysisProgress: 0,
        currentTest: null,
      });
    }
  },

  // Complete analysis
  completeAnalysis: (results) => {
    set({
      isAnalyzing: false,
      analysisResults: results,
      analysisProgress: 100,
      analysisTests: get().analysisTests.map((test) => ({
        ...test,
        status: "completed",
        progress: 100,
      })),
    });

    // Scroll to results section with a slight delay to ensure DOM is updated
    setTimeout(() => {
      scrollToSection("results", 100);
    }, 300);
  },

  // Simulate analysis progress for better UX
  simulateAnalysisProgress: () => {
    let progress = 0;
    let testIndex = 0;

    const progressInterval = setInterval(() => {
      const currentState = get();
      const tests = [...currentState.analysisTests];

      // Update current test progress
      if (testIndex < tests.length) {
        const currentTest = tests[testIndex];

        // More realistic progress increments
        const increment = Math.random() * 12 + 3; // 3-15% increments
        currentTest.progress += increment;

        if (currentTest.progress >= 100) {
          currentTest.progress = 100;
          currentTest.status = "completed";
          testIndex++;

          if (testIndex < tests.length) {
            tests[testIndex].status = "running";
          }
        } else {
          currentTest.status = "running";
        }
      }

      // Update overall progress based on completed tests and current test progress
      const completedTests = testIndex;
      const currentTestProgress =
        testIndex < tests.length ? tests[testIndex].progress / 100 : 0;
      progress = Math.min(
        95,
        ((completedTests + currentTestProgress) / tests.length) * 100
      );

      set({
        analysisProgress: progress,
        currentTest: testIndex < tests.length ? tests[testIndex].id : null,
        analysisTests: tests,
      });

      // Stop at 95% to wait for actual API response
      if (progress >= 95 || testIndex >= tests.length) {
        clearInterval(progressInterval);
      }
    }, 600 + Math.random() * 600); // Random interval between 600-1200ms

    return progressInterval;
  },

  // Report generation state
  isGeneratingReport: false,
  reportError: null,
  setGeneratingReport: (generating) => set({ isGeneratingReport: generating }),
  setReportError: (error) => set({ reportError: error }),

  // Batch report generation state
  isGeneratingBatchReport: false,
  batchReportError: null,
  setGeneratingBatchReport: (generating) =>
    set({ isGeneratingBatchReport: generating }),
  setBatchReportError: (error) => set({ batchReportError: error }),

  // Threat Feed state
  threatFeedData: null,
  threatFeedError: null,
  isLoadingThreatFeed: false,
  setThreatFeedData: (data) => set({ threatFeedData: data }),
  setThreatFeedError: (error) => set({ threatFeedError: error }),
  setLoadingThreatFeed: (loading) => set({ isLoadingThreatFeed: loading }),

  // Abuse reporting state
  isReportingAbuse: false,
  abuseReportError: null,
  setReportingAbuse: (reporting) => set({ isReportingAbuse: reporting }),
  setAbuseReportError: (error) => set({ abuseReportError: error }),

  // Load threat feed data
  loadThreatFeed: async () => {
    set({ isLoadingThreatFeed: true, threatFeedError: null });

    try {
      const response = await APKAnalysisService.getThreatFeed();
      set({
        threatFeedData: response.data.feed,
        isLoadingThreatFeed: false,
      });
    } catch (error) {
      console.error("Failed to load threat feed:", error);

      let errorMessage = "Failed to load threat feed";
      if (error.response?.status >= 500) {
        errorMessage =
          "Server error loading threat feed. Please try again later.";
      } else if (error.message) {
        errorMessage = `Threat feed error: ${error.message}`;
      }

      set({
        threatFeedError: errorMessage,
        isLoadingThreatFeed: false,
      });
    }
  },

  // Submit threat intelligence
  submitThreatIntelligence: async (hashes, packages, certFingerprints) => {
    set({ isLoadingThreatFeed: true, threatFeedError: null });

    try {
      const response = await APKAnalysisService.submitThreatIntelligence(
        hashes,
        packages,
        certFingerprints
      );

      // Reload threat feed data after successful submission
      if (response.data.status === "success") {
        await get().loadThreatFeed();
        return true;
      } else {
        throw new Error(
          response.data.detail || "Failed to submit threat intelligence"
        );
      }
    } catch (error) {
      console.error("Failed to submit threat intelligence:", error);

      let errorMessage = "Failed to submit threat intelligence";
      if (error.response?.data?.detail) {
        errorMessage = error.response.data.detail;
      } else if (error.message) {
        errorMessage = error.message;
      }

      set({
        threatFeedError: errorMessage,
        isLoadingThreatFeed: false,
      });
      return false;
    }
  },

  // Report malicious APK
  reportAbuse: async (file, reporterEmail, reporterName, additionalNotes) => {
    set({ isReportingAbuse: true, abuseReportError: null });

    try {
      const response = await APKAnalysisService.reportAbuse(
        file,
        reporterEmail,
        reporterName,
        additionalNotes
      );

      if (response.data.status === "success") {
        // Reload threat feed data after successful abuse report
        await get().loadThreatFeed();

        set({ isReportingAbuse: false });
        return {
          success: true,
          evidenceBundle: response.data.evidence_bundle,
        };
      } else {
        throw new Error(
          response.data.detail || "Failed to submit abuse report"
        );
      }
    } catch (error) {
      console.error("Failed to submit abuse report:", error);

      let errorMessage = "Failed to submit abuse report";
      if (error.response?.data?.detail) {
        errorMessage = error.response.data.detail;
      } else if (error.message) {
        errorMessage = error.message;
      }

      set({
        abuseReportError: errorMessage,
        isReportingAbuse: false,
      });
      return { success: false, error: errorMessage };
    }
  },

  // Report multiple malicious APKs
  reportBatchAbuse: async (files, reporterEmail, reporterName, additionalNotes) => {
    set({ isReportingAbuse: true, abuseReportError: null });

    try {
      const response = await APKAnalysisService.reportBatchAbuse(
        files,
        reporterEmail,
        reporterName,
        additionalNotes
      );

      if (response.data.status === "success") {
        // Reload threat feed data after successful batch abuse report
        await get().loadThreatFeed();

        set({ isReportingAbuse: false });
        return {
          success: true,
          evidenceBundle: response.data.evidence_bundles,
          maliciousCount: response.data.malicious_count,
          totalAnalyzed: response.data.total_analyzed,
        };
      } else {
        throw new Error(
          response.data.detail || "Failed to submit batch abuse report"
        );
      }
    } catch (error) {
      console.error("Failed to submit batch abuse report:", error);

      let errorMessage = "Failed to submit batch abuse report";
      if (error.response?.data?.detail) {
        errorMessage = error.response.data.detail;
      } else if (error.message) {
        errorMessage = error.message;
      }

      set({
        abuseReportError: errorMessage,
        isReportingAbuse: false,
      });
      return { success: false, error: errorMessage };
    }
  },

  // Generate and Download Detailed Report - now uses batch endpoint for consistency
  generateHTMLReport: async () => {
    const state = get();
    if (!state.uploadedFile) {
      set({ reportError: "No file uploaded for report generation" });
      return false;
    }

    set({ isGeneratingReport: true, reportError: null });

    try {
      // Use the batch report endpoint for single files too
      const response = await APKAnalysisService.generateBatchReport([
        state.uploadedFile.file || state.uploadedFile,
      ]);

      if (response.data?.word_report) {
        // Create blob from base64 Word document content and download
        const base64Data = response.data.word_report;

        try {
          // Convert base64 to binary
          const binaryString = window.atob(base64Data);
          const bytes = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
          }

          const blob = new Blob([bytes], {
            type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          });

          // Create download link
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `${state.uploadedFile.name}_analysis_report_${
            new Date().toISOString().split("T")[0]
          }.docx`;
          document.body.appendChild(a);
          a.click();

          // Cleanup
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);

          set({ isGeneratingReport: false });
          return true;
        } catch (decodeError) {
          console.error("Failed to decode base64 report data:", decodeError);
          throw new Error("Failed to process report data");
        }
      } else {
        throw new Error(
          "Invalid report response format - no word_report field"
        );
      }
    } catch (error) {
      console.error("Report generation failed:", error);

      let errorMessage;
      if (error.code === "ECONNABORTED" || error.message.includes("timeout")) {
        errorMessage = "Report generation timed out. Please try again.";
      } else if (error.response?.status === 400) {
        const detail =
          error.response.data?.detail || error.response.data?.error;
        errorMessage = detail || "Invalid request for report generation.";
      } else if (error.response?.status === 422) {
        errorMessage = "Could not analyze APK for report generation.";
      } else if (error.response?.status >= 500) {
        errorMessage =
          "Server error during report generation. Please try again later.";
      } else {
        errorMessage =
          error.response?.data?.error ||
          error.message ||
          "Unknown error occurred";
      }

      set({
        reportError: `Report generation failed: ${errorMessage}`,
        isGeneratingReport: false,
      });
      return false;
    }
  },

  // Generate and download batch Word report
  generateBatchReport: async (files) => {
    if (!files || files.length === 0) {
      set({
        batchReportError: "No files provided for batch report generation",
      });
      return false;
    }

    set({ isGeneratingBatchReport: true, batchReportError: null });

    try {
      const response = await APKAnalysisService.generateBatchReport(files);

      if (response.data?.word_report) {
        // Create blob from base64 Word document content and download
        const base64Data = response.data.word_report;

        try {
          // Convert base64 to binary
          const binaryString = window.atob(base64Data);
          const bytes = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
          }

          const blob = new Blob([bytes], {
            type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          });

          // Create download link
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `batch_analysis_report_${
            new Date().toISOString().split("T")[0]
          }.docx`;
          document.body.appendChild(a);
          a.click();

          // Cleanup
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);

          set({ isGeneratingBatchReport: false });
          return true;
        } catch (decodeError) {
          console.error("Failed to decode base64 report data:", decodeError);
          throw new Error("Failed to process report data");
        }
      } else {
        throw new Error(
          "Invalid batch report response format - no word_report field"
        );
      }
    } catch (error) {
      console.error("Batch report generation failed:", error);

      let errorMessage;
      if (error.code === "ECONNABORTED" || error.message.includes("timeout")) {
        errorMessage = "Batch report generation timed out. Please try again.";
      } else if (error.response?.status === 400) {
        const detail =
          error.response.data?.detail || error.response.data?.error;
        if (detail === "Maximum 15 files allowed per batch") {
          errorMessage = "Maximum 15 files allowed per batch report.";
        } else if (detail === "No valid APK files found") {
          errorMessage = "No valid APK files found for batch report.";
        } else {
          errorMessage = detail || "Invalid request for batch report.";
        }
      } else if (error.response?.status === 422) {
        errorMessage =
          "Could not analyze one or more APK files for batch report.";
      } else if (error.response?.status >= 500) {
        errorMessage =
          "Server error during batch report generation. Please try again later.";
      } else {
        errorMessage =
          error.response?.data?.error ||
          error.message ||
          "Unknown error occurred";
      }

      set({
        batchReportError: `Batch report generation failed: ${errorMessage}`,
        isGeneratingBatchReport: false,
      });
      return false;
    }
  },

  // Reset all state for new analysis
  resetApp: () => {
    set({
      uploadedFile: null,
      isUploading: false,
      uploadError: null,
      isAnalyzing: false,
      analysisResults: null,
      reportError: null,
      isGeneratingReport: false,
      batchReportError: null,
      isGeneratingBatchReport: false,
      analysisProgress: 0,
      currentTest: null,
      analysisTests: get().analysisTests.map((test) => ({
        ...test,
        status: "pending",
        progress: 0,
      })),
    });

    // Scroll to upload section for new analysis
    setTimeout(() => {
      scrollToSection("upload", 100);
    }, 100);
  },
}));

export default useAppStore;
