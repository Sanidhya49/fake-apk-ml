import React, { useRef, useState } from "react";
import {
  HiUpload,
  HiX,
  HiDocumentText,
  HiExclamation,
  HiDownload,
} from "react-icons/hi";
import { BsFileEarmarkZip, BsShieldFillCheck } from "react-icons/bs";
import { HiQueueList, HiTrash } from "react-icons/hi2";
import useAppStore from "../../store/useAppStore";
import { validateAPKFile, createFilePreview } from "../../utils/fileUtils";
import BatchAbuseReportModal from "./BatchAbuseReportModal";

const BatchUploadSection = () => {
  const fileInputRef = useRef(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [uploadMode, setUploadMode] = useState("single"); // "single" or "batch"
  const [batchFiles, setBatchFiles] = useState([]);
  const [batchResults, setBatchResults] = useState(null);
  const [isBatchAnalyzing, setIsBatchAnalyzing] = useState(false);
  const [batchError, setBatchError] = useState(null);
  const [showBatchAbuseModal, setShowBatchAbuseModal] = useState(false);

  const {
    uploadedFile,
    isUploading,
    uploadError,
    isAnalyzing,
    setUploadedFile,
    setUploading,
    setUploadError,
    clearFile,
    startAnalysis,
    generateBatchReport,
    isGeneratingBatchReport,
  } = useAppStore();

  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    const files = Array.from(e.dataTransfer.files);
    if (uploadMode === "single" && files.length > 0) {
      handleFileSelection(files[0]);
    } else if (uploadMode === "batch" && files.length > 0) {
      // Check file limit before processing
      const totalFiles = batchFiles.length + files.length;
      if (totalFiles > 15) {
        setBatchError(
          `Maximum 15 files allowed per batch. You're trying to add ${
            files.length
          } files but already have ${batchFiles.length} files. Please remove ${
            totalFiles - 15
          } files.`
        );
        return;
      }
      handleBatchFileSelection(files);
    }
  };

  const handleFileInputChange = (e) => {
    const files = Array.from(e.target.files);
    if (uploadMode === "single" && files.length > 0) {
      handleFileSelection(files[0]);
    } else if (uploadMode === "batch" && files.length > 0) {
      // Check file limit before processing
      const totalFiles = batchFiles.length + files.length;
      if (totalFiles > 15) {
        setBatchError(
          `Maximum 15 files allowed per batch. You're trying to add ${
            files.length
          } files but already have ${batchFiles.length} files. Please remove ${
            totalFiles - 15
          } files.`
        );
        return;
      }
      handleBatchFileSelection(files);
    }
  };

  const handleFileSelection = (file) => {
    setUploading(true);

    // Validate file
    const validation = validateAPKFile(file);
    if (!validation.isValid) {
      setUploadError(validation.error);
      setUploading(false);
      return;
    }

    // Simulate upload delay
    setTimeout(() => {
      const filePreview = createFilePreview(file);
      setUploadedFile({ ...filePreview, file });
      setUploading(false);
    }, 800);
  };

  const handleBatchFileSelection = (files) => {
    setBatchError(null);
    const validFiles = [];
    const errors = [];

    // Check total file limit (existing + new files)
    const totalFiles = batchFiles.length + files.length;
    if (totalFiles > 15) {
      setBatchError(
        `Maximum 15 files allowed per batch. You're trying to add ${
          files.length
        } files but already have ${batchFiles.length} files. Please remove ${
          totalFiles - 15
        } files.`
      );
      return;
    }

    files.forEach((file, index) => {
      const validation = validateAPKFile(file);
      if (validation.isValid) {
        validFiles.push({
          id: Date.now() + index,
          file,
          preview: createFilePreview(file),
          status: "pending", // pending, analyzing, completed, error
          result: null,
        });
      } else {
        errors.push(`${file.name}: ${validation.error}`);
      }
    });

    if (errors.length > 0) {
      setBatchError(`Some files were rejected: ${errors.join(", ")}`);
    }

    setBatchFiles((prev) => [...prev, ...validFiles]);
  };

  const removeBatchFile = (id) => {
    setBatchFiles((prev) => prev.filter((f) => f.id !== id));
  };

  const clearBatchFiles = () => {
    setBatchFiles([]);
    setBatchResults(null);
    setBatchError(null);
  };

  const handleBatchAnalysis = async () => {
    if (batchFiles.length === 0) return;

    setIsBatchAnalyzing(true);
    setBatchError(null);
    setBatchResults(null);

    try {
      // Import the API service
      const { APKAnalysisService } = await import("../../services/api");

      // Prepare files for batch analysis
      const filesToAnalyze = batchFiles.map((f) => f.file);

      console.log(
        "Starting batch analysis for",
        filesToAnalyze.length,
        "files"
      );

      // Make batch API call
      const response = await APKAnalysisService.scanBatch(
        filesToAnalyze,
        false,
        false
      );

      console.log("Batch analysis response:", response.data);

      // Process results
      const results = response.data.results;
      setBatchResults(results);

      // Update file statuses
      setBatchFiles((prev) =>
        prev.map((file) => {
          const result = results.find((r) => r.file === file.file.name);
          return {
            ...file,
            status: result ? (result.error ? "error" : "completed") : "error",
            result: result || { error: "No result received" },
          };
        })
      );
    } catch (error) {
      console.error("Batch analysis failed:", error);
      setBatchError(
        `Batch analysis failed: ${error.response?.data?.error || error.message}`
      );

      // Mark all files as error
      setBatchFiles((prev) =>
        prev.map((file) => ({
          ...file,
          status: "error",
          result: { error: "Analysis failed" },
        }))
      );
    } finally {
      setIsBatchAnalyzing(false);
    }
  };

  const handleDownloadBatchReport = async () => {
    if (batchFiles.length === 0) return;

    const filesToReport = batchFiles.map((f) => f.file);
    const success = await generateBatchReport(filesToReport);

    if (success) {
      console.log("Batch Word report downloaded successfully");
    }
  };

  const handleBrowseFiles = () => {
    if (fileInputRef.current) {
      fileInputRef.current.multiple = uploadMode === "batch";
      fileInputRef.current.click();
    }
  };

  const handleStartAnalysis = () => {
    if (uploadedFile) {
      startAnalysis();
    }
  };

  // Mode switch handler
  const switchMode = (mode) => {
    setUploadMode(mode);
    clearFile();
    clearBatchFiles();
  };

  return (
    <section
      id="upload"
      className="py-8 md:py-16 bg-gray-50 dark:bg-gray-800 relative overflow-hidden"
    >
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-2">
        <div className="absolute inset-0 bg-grid-pattern"></div>
      </div>

      <div className="relative z-10 max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-12 animate-fade-up">
          <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold text-gray-900 dark:text-white mb-4">
            Upload APK for
            <span className="block text-transparent bg-clip-text bg-gradient-to-r from-primary-400 to-teal-400">
              Security Analysis
            </span>
          </h2>
          <p className="text-xl text-gray-300">
            Analyze single APK files or batch process multiple files
          </p>
        </div>

        {/* Mode Selector */}
        <div
          className="flex justify-center mb-8 animate-fade-up"
          style={{ animationDelay: "100ms" }}
        >
          <div className="bg-white dark:bg-gray-900 p-1 rounded-xl border border-gray-700">
            <button
              onClick={() => switchMode("single")}
              className={`px-6 py-3 rounded-lg font-medium transition-all duration-200 ${
                uploadMode === "single"
                  ? "bg-primary-500 text-white shadow-lg"
                  : "text-gray-400 hover:text-gray-900 dark:hover:text-gray-200"
              }`}
            >
              Single File
            </button>
            <button
              onClick={() => switchMode("batch")}
              className={`px-6 py-3 rounded-lg font-medium transition-all duration-200 ${
                uploadMode === "batch"
                  ? "bg-primary-500 text-white shadow-lg"
                  : "text-gray-400 hover:text-gray-900 dark:hover:text-gray-200"
              }`}
            >
              <HiQueueList className="w-4 h-4 inline mr-2" />
              Batch Analysis
            </button>
          </div>
        </div>

        {/* Single File Mode */}
        {uploadMode === "single" && (
          <>
            {/* Upload Area */}
            {!uploadedFile ? (
              <div
                className="animate-fade-up"
                style={{ animationDelay: "200ms" }}
              >
                <div
                  className={`relative p-8 md:p-12 border-2 border-dashed rounded-2xl transition-all duration-300 ${
                    isDragOver
                      ? "border-primary-400 bg-primary-50 dark:bg-primary-900/20 scale-105"
                      : "border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 hover:border-primary-400 dark:hover:border-primary-500"
                  } ${
                    isUploading
                      ? "pointer-events-none opacity-75"
                      : "cursor-pointer"
                  }`}
                  onDragEnter={handleDragEnter}
                  onDragLeave={handleDragLeave}
                  onDragOver={handleDragOver}
                  onDrop={handleDrop}
                  onClick={handleBrowseFiles}
                >
                  {/* Upload Icon */}
                  <div className="text-center">
                    <div
                      className={`inline-flex items-center justify-center w-20 h-20 rounded-full mb-6 ${
                        isDragOver
                          ? "bg-primary-100 dark:bg-primary-900/40 animate-pulse"
                          : "bg-gray-100 dark:bg-gray-700"
                      } transition-all duration-300`}
                    >
                      {isUploading ? (
                        <div className="animate-spin rounded-full h-10 w-10 border-4 border-primary-500 border-t-transparent"></div>
                      ) : (
                        <BsFileEarmarkZip
                          className={`w-10 h-10 ${
                            isDragOver
                              ? "text-primary-500"
                              : "text-gray-400 dark:text-gray-500"
                          } transition-colors duration-300`}
                        />
                      )}
                    </div>

                    {/* Upload Text */}
                    <h3 className="text-2xl font-semibold text-gray-900 dark:text-white mb-2">
                      {isUploading
                        ? "Processing..."
                        : "Drop your APK file here"}
                    </h3>
                    <p className="text-gray-400 mb-6">
                      {isUploading
                        ? "Validating file..."
                        : "or click to browse your device"}
                    </p>

                    {/* Browse Button */}
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleBrowseFiles();
                      }}
                      disabled={isUploading}
                      className="inline-flex items-center px-8 py-3 bg-gradient-to-r from-primary-600 to-teal-600 hover:from-primary-700 hover:to-teal-700 disabled:from-gray-400 disabled:to-gray-500 text-white font-medium rounded-xl shadow-lg hover:shadow-xl transform hover:-translate-y-1 disabled:transform-none transition-all duration-300"
                    >
                      <HiUpload className="w-5 h-5 mr-2" />
                      {isUploading ? "Processing..." : "Browse Files"}
                    </button>
                  </div>

                  {/* Scanning Animation Overlay */}
                  {isUploading && (
                    <div className="absolute inset-0 rounded-2xl overflow-hidden">
                      <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-primary-400 to-teal-400 transform -translate-x-full animate-scan"></div>
                    </div>
                  )}
                </div>

                {/* Error Message */}
                {uploadError && (
                  <div className="mt-6 p-4 rounded-lg bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-700/50 animate-fade-in">
                    <div className="flex items-center">
                      <HiExclamation className="w-5 h-5 text-danger-500 mr-3" />
                      <p className="text-danger-700 dark:text-danger-300 font-medium">
                        {uploadError}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              /* File Preview */
              <div className="animate-fade-up">
                <div className="p-6 md:p-8 bg-white dark:bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
                      File Ready for Analysis
                    </h3>
                    <button
                      onClick={clearFile}
                      disabled={isAnalyzing}
                      className="p-2 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <HiX className="w-5 h-5" />
                    </button>
                  </div>

                  {/* File Details */}
                  <div className="flex items-center space-x-4 mb-6">
                    <div className="flex-shrink-0">
                      <div className="w-12 h-12 bg-primary-100 dark:bg-primary-900/40 rounded-lg flex items-center justify-center">
                        <HiDocumentText className="w-6 h-6 text-primary-400" />
                      </div>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-lg font-medium text-gray-900 dark:text-white truncate">
                        {uploadedFile.name}
                      </p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        {uploadedFile.formattedSize} • APK File
                      </p>
                    </div>
                  </div>

                  {/* Analysis Button */}
                  <button
                    onClick={handleStartAnalysis}
                    disabled={isAnalyzing}
                    className="w-full inline-flex items-center justify-center px-8 py-4 bg-gradient-to-r from-success-600 to-teal-600 hover:from-success-700 hover:to-teal-700 disabled:from-gray-400 disabled:to-gray-500 text-white font-semibold rounded-xl shadow-lg hover:shadow-xl transform hover:-translate-y-1 disabled:transform-none transition-all duration-300"
                  >
                    {isAnalyzing ? (
                      <>
                        <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent mr-2"></div>
                        Analyzing APK...
                      </>
                    ) : (
                      <>
                        <HiUpload className="w-5 h-5 mr-2" />
                        Start Security Analysis
                      </>
                    )}
                  </button>

                  <p className="text-center text-sm text-gray-500 dark:text-gray-400 mt-4">
                    {isAnalyzing
                      ? "Please wait while we analyze your APK file..."
                      : "Analysis typically takes 15-30 seconds"}
                  </p>
                </div>
              </div>
            )}
          </>
        )}

        {/* Batch Mode */}
        {uploadMode === "batch" && (
          <div className="animate-fade-up" style={{ animationDelay: "200ms" }}>
            {/* Batch Upload Area */}
            <div
              className={`relative p-8 md:p-12 border-2 border-dashed rounded-2xl transition-all duration-300 mb-6 ${
                isDragOver
                  ? "border-primary-400 bg-primary-50 dark:bg-primary-900/20 scale-105"
                  : "border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 hover:border-primary-400 dark:hover:border-primary-500"
              } cursor-pointer`}
              onDragEnter={handleDragEnter}
              onDragLeave={handleDragLeave}
              onDragOver={handleDragOver}
              onDrop={handleDrop}
              onClick={handleBrowseFiles}
            >
              <div className="text-center">
                <div className="inline-flex items-center justify-center w-20 h-20 rounded-full mb-6 bg-gradient-to-r from-primary-100 to-accent-100 dark:from-primary-900/40 dark:to-accent-900/40">
                  <HiQueueList className="w-10 h-10 text-primary-400" />
                </div>

                <h3 className="text-2xl font-semibold text-gray-900 dark:text-white mb-2">
                  Drop multiple APK files here
                </h3>
                <p className="text-gray-400 mb-6">
                  Select multiple files for batch analysis (up to 15 files)
                </p>

                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleBrowseFiles();
                  }}
                  className="inline-flex items-center px-8 py-3 bg-gradient-to-r from-accent-600 to-primary-600 hover:from-accent-700 hover:to-primary-700 text-white font-medium rounded-xl shadow-lg hover:shadow-xl transform hover:-translate-y-1 transition-all duration-300"
                >
                  <HiQueueList className="w-5 h-5 mr-2" />
                  Select Multiple Files
                </button>
              </div>
            </div>

            {/* Batch Error */}
            {batchError && (
              <div className="mb-6 p-4 rounded-lg bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-700/50">
                <div className="flex items-center">
                  <HiExclamation className="w-5 h-5 text-danger-500 mr-3" />
                  <p className="text-danger-700 dark:text-danger-300 font-medium">
                    {batchError}
                  </p>
                </div>
              </div>
            )}

            {/* Batch Files List */}
            {batchFiles.length > 0 && (
              <div className="bg-white dark:bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg overflow-hidden">
                <div className="p-6 border-b border-gray-700">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
                      Batch Analysis Queue ({batchFiles.length}/15 files)
                    </h3>
                    <div className="flex items-center space-x-3">
                      <button
                        onClick={clearBatchFiles}
                        disabled={isBatchAnalyzing}
                        className="px-4 py-2 text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-all duration-200 disabled:opacity-50"
                      >
                        <HiTrash className="w-4 h-4 mr-2 inline" />
                        Clear All
                      </button>
                      <button
                        onClick={handleBatchAnalysis}
                        disabled={isBatchAnalyzing || batchFiles.length === 0}
                        className="px-6 py-2 bg-gradient-to-r from-success-600 to-teal-600 hover:from-success-700 hover:to-teal-700 disabled:from-gray-400 disabled:to-gray-500 text-white font-medium rounded-lg shadow-lg hover:shadow-xl transition-all duration-300"
                      >
                        {isBatchAnalyzing ? (
                          <>
                            <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent mr-2 inline-block"></div>
                            Analyzing...
                          </>
                        ) : (
                          "Start Batch Analysis"
                        )}
                      </button>
                    </div>
                  </div>
                  {/* File limit warnings */}
                  {batchFiles.length >= 12 && batchFiles.length < 15 && (
                    <div className="px-6 pb-3">
                      <p className="text-xs text-amber-600 dark:text-amber-400">
                        {15 - batchFiles.length} more files allowed
                      </p>
                    </div>
                  )}
                  {batchFiles.length === 15 && (
                    <div className="px-6 pb-3">
                      <p className="text-xs text-red-600 dark:text-red-400">
                        Maximum file limit reached (15/15)
                      </p>
                    </div>
                  )}
                </div>

                <div className="divide-y divide-gray-200 dark:divide-gray-700">
                  {batchFiles.map((fileItem) => (
                    <div key={fileItem.id} className="p-6">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-4">
                          <div className="flex-shrink-0">
                            <div
                              className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                                fileItem.status === "completed"
                                  ? "bg-success-100 dark:bg-success-900/40"
                                  : fileItem.status === "error"
                                  ? "bg-danger-100 dark:bg-danger-900/40"
                                  : fileItem.status === "analyzing"
                                  ? "bg-primary-100 dark:bg-primary-900/40"
                                  : "bg-gray-100 dark:bg-gray-700"
                              }`}
                            >
                              <HiDocumentText
                                className={`w-5 h-5 ${
                                  fileItem.status === "completed"
                                    ? "text-success-600 dark:text-success-400"
                                    : fileItem.status === "error"
                                    ? "text-danger-600 dark:text-danger-400"
                                    : fileItem.status === "analyzing"
                                    ? "text-primary-400"
                                    : "text-gray-500 dark:text-gray-400"
                                }`}
                              />
                            </div>
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                              {fileItem.preview.name}
                            </p>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                              {fileItem.preview.formattedSize}
                            </p>
                          </div>
                        </div>

                        <div className="flex items-center space-x-3">
                          {/* Status */}
                          <span
                            className={`px-3 py-1 rounded-full text-xs font-medium ${
                              fileItem.status === "completed"
                                ? "bg-success-100 dark:bg-success-900/40 text-success-700 dark:text-success-300"
                                : fileItem.status === "error"
                                ? "bg-danger-100 dark:bg-danger-900/40 text-danger-700 dark:text-danger-300"
                                : fileItem.status === "analyzing"
                                ? "bg-primary-100 dark:bg-primary-900/40 text-primary-700 dark:text-primary-300"
                                : "bg-gray-100 dark:bg-gray-700 text-gray-400"
                            }`}
                          >
                            {fileItem.status === "completed" && "✓ Completed"}
                            {fileItem.status === "error" && "✗ Error"}
                            {fileItem.status === "analyzing" && "⟳ Analyzing"}
                            {fileItem.status === "pending" && "⏳ Pending"}
                          </span>

                          {/* Result */}
                          {fileItem.result && !fileItem.result.error && (
                            <span
                              className={`px-2 py-1 rounded text-xs font-medium ${
                                fileItem.result.prediction === "fake"
                                  ? "bg-danger-100 dark:bg-danger-900/40 text-danger-700 dark:text-danger-300"
                                  : "bg-success-100 dark:bg-success-900/40 text-success-700 dark:text-success-300"
                              }`}
                            >
                              {fileItem.result.prediction} (
                              {Math.round(fileItem.result.probability * 100)}%)
                            </span>
                          )}

                          {/* Remove button */}
                          <button
                            onClick={() => removeBatchFile(fileItem.id)}
                            disabled={isBatchAnalyzing}
                            className="p-1 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 rounded transition-all duration-200 disabled:opacity-50"
                          >
                            <HiX className="w-4 h-4" />
                          </button>
                        </div>
                      </div>

                      {/* Error details */}
                      {fileItem.result?.error && (
                        <div className="mt-3 p-3 rounded-lg bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-700/50">
                          <p className="text-sm text-danger-700 dark:text-danger-300">
                            {fileItem.result.error}
                          </p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Batch Results Summary */}
            {batchResults && (
              <div className="mt-6 bg-white dark:bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
                    Batch Analysis Results
                  </h3>

                  <div className="flex items-center space-x-3">
                    {/* Download Report Button */}
                    <button
                      onClick={handleDownloadBatchReport}
                      disabled={
                        isGeneratingBatchReport || batchFiles.length === 0
                      }
                      className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-primary-600 to-teal-600 hover:from-primary-700 hover:to-teal-700 disabled:from-gray-400 disabled:to-gray-500 text-white font-medium rounded-lg shadow-lg hover:shadow-xl transition-all duration-300 disabled:cursor-not-allowed"
                    >
                      {isGeneratingBatchReport ? (
                        <>
                          <div className="w-4 h-4 mr-2 animate-spin border-2 border-white border-t-transparent rounded-full" />
                          Generating...
                        </>
                      ) : (
                        <>
                          <HiDownload className="w-4 h-4 mr-2" />
                          Download Report
                        </>
                      )}
                    </button>

                    {/* Report Malicious APKs Button */}
                    {batchResults && batchResults.some(r => r.prediction === "fake") && (
                      <button
                        onClick={() => setShowBatchAbuseModal(true)}
                        className="inline-flex items-center px-4 py-2 bg-gradient-to-r from-danger-600 to-red-600 hover:from-danger-700 hover:to-red-700 text-white font-medium rounded-lg shadow-lg hover:shadow-xl transition-all duration-300"
                      >
                        <HiExclamation className="w-4 h-4 mr-2" />
                        Report Malicious APKs ({batchResults.filter(r => r.prediction === "fake").length})
                      </button>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <div className="text-2xl font-bold text-gray-900 dark:text-white">
                      {batchResults.length}
                    </div>
                    <div className="text-sm text-gray-400">
                      Total Files
                    </div>
                  </div>

                  <div className="text-center p-4 bg-success-50 dark:bg-success-900/20 rounded-lg">
                    <div className="text-2xl font-bold text-success-600 dark:text-success-400">
                      {
                        batchResults.filter((r) => r.prediction === "legit")
                          .length
                      }
                    </div>
                    <div className="text-sm text-success-600 dark:text-success-400">
                      Safe
                    </div>
                  </div>

                  <div className="text-center p-4 bg-danger-50 dark:bg-danger-900/20 rounded-lg">
                    <div className="text-2xl font-bold text-danger-600 dark:text-danger-400">
                      {
                        batchResults.filter((r) => r.prediction === "fake")
                          .length
                      }
                    </div>
                    <div className="text-sm text-danger-600 dark:text-danger-400">
                      Threats
                    </div>
                  </div>

                  <div className="text-center p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <div className="text-2xl font-bold text-gray-900 dark:text-white">
                      {batchResults.filter((r) => r.error).length}
                    </div>
                    <div className="text-sm text-gray-400">
                      Errors
                    </div>
                  </div>
                </div>

                {/* Report Description */}
                <div className="mt-4 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700/50 rounded-lg">
                  <div className="flex items-start space-x-3">
                    <HiDocumentText className="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <h4 className="font-medium text-blue-700 dark:text-blue-300 mb-1">
                        Comprehensive Analysis Report
                      </h4>
                      <p className="text-sm text-blue-600 dark:text-blue-400">
                        Download a detailed Word document containing complete
                        analysis results, security assessments, and AI-powered
                        explanations for all processed APK files.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Sample APKs */}
        <div
          className="mt-12 animate-fade-up"
          style={{ animationDelay: "500ms" }}
        >
          <div className="text-center mb-8">
            <h3 className="text-2xl md:text-3xl font-bold text-gray-900 dark:text-white mb-2">
              Download Sample APKs
            </h3>
            <p className="text-gray-300">
              Test our detection system with pre-verified real and fake banking
              apps
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {/* Real APKs */}
            <div className="bg-white dark:bg-gray-900 rounded-2xl border border-success-200 dark:border-success-700/30 shadow-lg overflow-hidden">
              <div className="p-6 border-b border-success-100 dark:border-success-700/30 bg-success-50 dark:bg-success-900/20">
                <h4 className="flex items-center text-xl font-bold text-success-700 dark:text-success-400">
                  <BsShieldFillCheck className="w-5 h-5 mr-2" />
                  Legitimate Banking APKs
                </h4>
              </div>

              <div className="p-6 space-y-4">
                <p className="text-sm text-gray-400">
                  These are verified, legitimate banking applications that our
                  system should identify as safe:
                </p>

                <div className="grid grid-cols-1 gap-3">
                  <div className="relative border border-gray-700 rounded-lg p-4 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-200">
                    <div>
                      <h5 className="font-medium text-gray-900 dark:text-white">
                        Jana Bank App
                      </h5>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        com.janabank.mtc_2.3.1.apk
                      </p>
                    </div>
                    <a
                      href="/sample/real/com.janabank.mtc_2.3.1.apk"
                      download
                      className="px-3 py-1 bg-gradient-to-r from-success-500 to-success-600 hover:from-success-600 hover:to-success-700 text-white text-sm font-medium rounded-lg flex items-center"
                    >
                      <HiDownload className="w-4 h-4 mr-1" />
                      Download
                    </a>
                  </div>

                  <div className="relative border border-gray-700 rounded-lg p-4 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-200">
                    <div>
                      <h5 className="font-medium text-gray-900 dark:text-white">
                        IMPS NE App
                      </h5>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        app.imps.north_east_4.5.0.apks.universal.apk
                      </p>
                    </div>
                    <a
                      href="/sample/real/app.imps.north_east_4.5.0.apks.universal.apk"
                      download
                      className="px-3 py-1 bg-gradient-to-r from-success-500 to-success-600 hover:from-success-600 hover:to-success-700 text-white text-sm font-medium rounded-lg flex items-center"
                    >
                      <HiDownload className="w-4 h-4 mr-1" />
                      Download
                    </a>
                  </div>

                  <div className="relative border border-gray-700 rounded-lg p-4 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-200">
                    <div>
                      <h5 className="font-medium text-gray-900 dark:text-white">
                        IOB Banking App
                      </h5>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        com.fss.iob6_6.5.8.apks.universal.apk
                      </p>
                    </div>
                    <a
                      href="/sample/real/com.fss.iob6_6.5.8.apks.universal.apk"
                      download
                      className="px-3 py-1 bg-gradient-to-r from-success-500 to-success-600 hover:from-success-600 hover:to-success-700 text-white text-sm font-medium rounded-lg flex items-center"
                    >
                      <HiDownload className="w-4 h-4 mr-1" />
                      Download
                    </a>
                  </div>
                </div>
              </div>
            </div>

            {/* Fake APKs */}
            <div className="bg-white dark:bg-gray-900 rounded-2xl border border-danger-200 dark:border-danger-700/30 shadow-lg overflow-hidden">
              <div className="p-6 border-b border-danger-100 dark:border-danger-700/30 bg-danger-50 dark:bg-danger-900/20">
                <h4 className="flex items-center text-xl font-bold text-danger-700 dark:text-danger-400">
                  <HiExclamation className="w-5 h-5 mr-2" />
                  Malicious Sample APKs
                </h4>
              </div>

              <div className="p-6 space-y-4">
                <p className="text-sm text-gray-400">
                  These are known malicious applications that our system should
                  identify as threats:
                </p>

                <div className="grid grid-cols-1 gap-3">
                  <div className="relative border border-gray-700 rounded-lg p-4 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-200">
                    <div>
                      <h5 className="font-medium text-gray-900 dark:text-white">
                        AES-Decrypt Malware
                      </h5>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        AES-Decrypt.apk
                      </p>
                    </div>
                    <a
                      href="/sample/fake/._AES-Decrypt.apk"
                      download
                      className="px-3 py-1 bg-gradient-to-r from-danger-500 to-danger-600 hover:from-danger-600 hover:to-danger-700 text-white text-sm font-medium rounded-lg flex items-center"
                    >
                      <HiDownload className="w-4 h-4 mr-1" />
                      Download
                    </a>
                  </div>

                  <div className="relative border border-gray-700 rounded-lg p-4 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-200">
                    <div>
                      <h5 className="font-medium text-gray-900 dark:text-white">
                        Native Exploit
                      </h5>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        aBunchOfNative.apk
                      </p>
                    </div>
                    <a
                      href="/sample/fake/._aBunchOfNative.apk"
                      download
                      className="px-3 py-1 bg-gradient-to-r from-danger-500 to-danger-600 hover:from-danger-600 hover:to-danger-700 text-white text-sm font-medium rounded-lg flex items-center"
                    >
                      <HiDownload className="w-4 h-4 mr-1" />
                      Download
                    </a>
                  </div>

                  <div className="relative border border-gray-700 rounded-lg p-4 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-200">
                    <div>
                      <h5 className="font-medium text-gray-900 dark:text-white">
                        Dynamic Challenge Trojan
                      </h5>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        dynChallenge.apk
                      </p>
                    </div>
                    <a
                      href="/sample/fake/._dynChallenge.apk"
                      download
                      className="px-3 py-1 bg-gradient-to-r from-danger-500 to-danger-600 hover:from-danger-600 hover:to-danger-700 text-white text-sm font-medium rounded-lg flex items-center"
                    >
                      <HiDownload className="w-4 h-4 mr-1" />
                      Download
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Hidden File Input */}
        <input
          ref={fileInputRef}
          type="file"
          accept=".apk,.apks,.xapk"
          multiple={uploadMode === "batch"}
          onChange={handleFileInputChange}
          className="hidden"
        />

        {/* Batch Abuse Report Modal */}
        <BatchAbuseReportModal
          isOpen={showBatchAbuseModal}
          onClose={() => setShowBatchAbuseModal(false)}
          maliciousFiles={batchFiles
            .filter(f => f.result && f.result.prediction === "fake")
            .map(f => f.file)}
          batchResults={batchResults}
        />
      </div>
    </section>
  );
};

export default BatchUploadSection;

