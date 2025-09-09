import axios from "axios";

// Create axios instance with base configuration
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "http://localhost:9000",
  timeout: 600000, // 10 minutes timeout to match backend processing time
  // Don't set default Content-Type header to allow FormData requests to work properly
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // You can add auth headers, logging, etc. here
    console.log(
      `Making ${config.method?.toUpperCase()} request to ${config.baseURL}${
        config.url
      }`
    );
    if (config.data instanceof FormData) {
      console.log("Request contains FormData with files");
      // Log FormData contents (for debugging)
      for (let [key, value] of config.data.entries()) {
        if (value instanceof File) {
          console.log(
            `FormData key: ${key}, File: ${value.name} (${value.size} bytes)`
          );
        } else {
          console.log(`FormData key: ${key}, Value: ${value}`);
        }
      }
    }
    return config;
  },
  (error) => {
    console.error("Request interceptor error:", error);
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    console.log(
      `Response received from ${response.config.url}:`,
      response.status
    );
    return response;
  },
  (error) => {
    if (error.response) {
      // Server responded with error status
      console.error(`API Error ${error.response.status}:`, error.response.data);
      console.error("Request URL:", error.config.url);
      console.error("Request method:", error.config.method);
    } else if (error.request) {
      // Request made but no response received
      console.error("No response received:", error.request);
      console.error("Request URL:", error.config?.url);
    } else {
      // Something else happened
      console.error("Request setup error:", error.message);
    }
    return Promise.reject(error);
  }
);

// APK Analysis Service
export class APKAnalysisService {
  /**
   * Analyze single APK file
   * @param {File} file - The APK file to analyze
   * @param {boolean} quick - Quick mode flag
   * @param {boolean} debug - Debug mode flag
   * @returns {Promise} Analysis result
   */
  static async scanSingle(file, quick = false, debug = false) {
    const formData = new FormData();
    formData.append("file", file);

    const params = new URLSearchParams();
    if (quick) params.append("quick", "true");
    if (debug) params.append("debug", "true");

    const url = `/scan${params.toString() ? "?" + params.toString() : ""}`;

    return api.post(url, formData, {
      timeout: 600000, // 10 minutes timeout to match Streamlit app
      headers: {
        "Content-Type": undefined, // Let browser set the Content-Type with boundary for FormData
      },
    });
  }

  /**
   * Analyze multiple APK files
   * @param {FileList|Array} files - The APK files to analyze
   * @param {boolean} quick - Quick mode flag
   * @param {boolean} debug - Debug mode flag
   * @returns {Promise} Analysis results
   */
  static async scanBatch(files, quick = false, debug = false) {
    const formData = new FormData();

    // Handle both FileList and Array
    const fileArray = Array.from(files);
    fileArray.forEach((file) => {
      formData.append("files", file);
    });

    const params = new URLSearchParams();
    if (quick) params.append("quick", "true");
    if (debug) params.append("debug", "true");

    const url = `/scan-batch${
      params.toString() ? "?" + params.toString() : ""
    }`;

    return api.post(url, formData, {
      timeout: 600000, // 10 minutes timeout
      headers: {
        "Content-Type": undefined, // Let browser set the Content-Type with boundary for FormData
      },
    });
  }

  /**
   * Generate report for APK
   * @param {File} file - The APK file
   * @returns {Promise} Report data with JSON and HTML
   */
  static async generateReport(file) {
    const formData = new FormData();
    formData.append("file", file);

    return api.post("/report", formData, {
      timeout: 600000, // 10 minutes timeout
      headers: {
        "Content-Type": undefined, // Let browser set the Content-Type with boundary for FormData
      },
    });
  }

  /**
   * Generate batch report for multiple APK files
   * @param {FileList|Array} files - The APK files to analyze
   * @returns {Promise} Batch report data with Word document
   */
  static async generateBatchReport(files) {
    const formData = new FormData();

    // Handle both FileList and Array
    const fileArray = Array.from(files);
    fileArray.forEach((file) => {
      formData.append("files", file);
    });

    return api.post("/report-batch", formData, {
      timeout: 900000, // 15 minutes timeout for batch processing
      headers: {
        "Content-Type": undefined, // Let browser set the Content-Type with boundary for FormData
      },
    });
  }

  /**
   * Health check endpoint
   * @returns {Promise} Server status
   */
  static async healthCheck() {
    return api.get("/", {
      headers: {
        "Content-Type": "application/json",
      },
    });
  }

  /**
   * Get threat feed status and statistics
   * @returns {Promise} Threat feed data
   */
  static async getThreatFeed() {
    return api.get("/threat-feed", {
      headers: {
        "Content-Type": "application/json",
      },
    });
  }

  /**
   * Submit threat intelligence indicators
   * @param {Array} hashes - Array of malicious file hashes
   * @param {Array} packages - Array of malicious package names
   * @param {Array} certFingerprints - Array of malicious certificate fingerprints
   * @returns {Promise} Submission result
   */
  static async submitThreatIntelligence(
    hashes = [],
    packages = [],
    certFingerprints = []
  ) {
    return api.post(
      "/threat/submit",
      {
        hashes,
        packages,
        cert_fingerprints: certFingerprints,
      },
      {
        headers: {
          "Content-Type": "application/json",
        },
      }
    );
  }

  /**
   * Report malicious APK with evidence bundle
   * @param {File} file - The APK file to report
   * @param {string} reporterEmail - Reporter's email address
   * @param {string} reporterName - Reporter's name
   * @param {string} additionalNotes - Additional notes about the report
   * @returns {Promise} Report submission result with evidence bundle
   */
  static async reportAbuse(
    file,
    reporterEmail,
    reporterName,
    additionalNotes = ""
  ) {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("reporter_email", reporterEmail);
    formData.append("reporter_name", reporterName);
    formData.append("additional_notes", additionalNotes);

    return api.post("/report-abuse", formData, {
      timeout: 600000, // 10 minutes timeout
      headers: {
        "Content-Type": undefined, // Let browser set the Content-Type with boundary for FormData
      },
    });
  }

  /**
   * Report multiple malicious APKs with evidence bundles
   * @param {File[]} files - Array of APK files to report
   * @param {string} reporterEmail - Reporter's email address
   * @param {string} reporterName - Reporter's name
   * @param {string} additionalNotes - Additional notes about the report
   * @returns {Promise} Batch report submission result with evidence bundles
   */
  static async reportBatchAbuse(
    files,
    reporterEmail,
    reporterName,
    additionalNotes = ""
  ) {
    const formData = new FormData();
    
    // Add all files
    files.forEach(file => {
      formData.append("files", file);
    });
    
    formData.append("reporter_email", reporterEmail);
    formData.append("reporter_name", reporterName);
    formData.append("additional_notes", additionalNotes);

    return api.post("/report-batch-abuse", formData, {
      timeout: 900000, // 15 minutes timeout for batch processing
      headers: {
        "Content-Type": undefined, // Let browser set the Content-Type with boundary for FormData
      },
    });
  }

  /**
   * Get available news categories
   * @returns {Promise} Available news categories with descriptions
   */
  static async getNewsCategories() {
    return api.get("/news/categories");
  }

  /**
   * Get enhanced news content with Gemini AI generation
   * @returns {Promise} Enhanced news content generated by AI
   */
  static async getEnhancedNews() {
    return api.get("/news/enhanced");
  }

  /**
   * Get news with optional enhancement
   * @param {boolean} enhanced - Whether to include AI-enhanced content
   * @returns {Promise} News data with optional AI enhancement
   */
  static async getNews(enhanced = false) {
    const params = enhanced ? { enhanced: 'true' } : {};
    return api.get("/news", { params });
  }
}

export default api;
