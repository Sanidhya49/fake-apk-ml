import React, { useRef, useState, useEffect } from "react";
import { HiUpload, HiX, HiDocumentText, HiExclamation } from "react-icons/hi";
import { BsFileEarmarkZip } from "react-icons/bs";
import useAppStore from "../../store/useAppStore";
import { validateAPKFile, createFilePreview } from "../../utils/fileUtils";
import { scrollToSection } from "../../utils/scrollUtils";

const UploadSection = () => {
  const fileInputRef = useRef(null);
  const [isDragOver, setIsDragOver] = useState(false);

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
  } = useAppStore();

  // Scroll to file preview section when file is successfully uploaded
  useEffect(() => {
    if (uploadedFile && !isUploading) {
      // Small delay to ensure DOM is updated and smooth scroll
      setTimeout(() => {
        scrollToSection("upload", 60);
      }, 200);
    }
  }, [uploadedFile, isUploading]);

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
    if (files.length > 0) {
      handleFileSelection(files[0]);
    }
  };

  const handleFileInputChange = (e) => {
    const files = Array.from(e.target.files);
    if (files.length > 0) {
      handleFileSelection(files[0]);
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

  const handleBrowseFiles = () => {
    fileInputRef.current?.click();
  };

  const handleStartAnalysis = () => {
    if (uploadedFile) {
      startAnalysis();
    }
  };

  return (
    <section
      id="upload"
      className="py-8 md:py-12 bg-gray-800 relative overflow-hidden"
    >
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-2">
        <div className="absolute inset-0 bg-grid-pattern"></div>
      </div>

      <div className="relative z-10 max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-8 animate-fade-up">
          <h2 className="text-2xl md:text-3xl lg:text-4xl font-bold text-white mb-3">
            Upload APK for
            <span className="block text-transparent bg-clip-text bg-gradient-to-r from-primary-400 to-teal-400">
              Security Analysis
            </span>
          </h2>
          <p className="text-lg text-gray-300">
            Drop your banking APK file here for comprehensive security analysis
          </p>
        </div>

        {/* Upload Area */}
        {!uploadedFile ? (
          <div className="animate-fade-up" style={{ animationDelay: "200ms" }}>
            <div
              className={`relative p-6 md:p-8 border-2 border-dashed rounded-2xl transition-all duration-300 ${
                isDragOver
                  ? "border-primary-400 bg-primary-900/20 scale-105"
                  : "border-gray-600 bg-gray-900 hover:border-primary-400 dark:hover:border-primary-500"
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
                  className={`inline-flex items-center justify-center w-16 h-16 rounded-full mb-4 ${
                    isDragOver
                      ? "bg-primary-100 dark:bg-primary-900/40 animate-pulse"
                      : "bg-gray-100 dark:bg-gray-700"
                  } transition-all duration-300`}
                >
                  {isUploading ? (
                    <div className="animate-spin rounded-full h-8 w-8 border-4 border-primary-500 border-t-transparent"></div>
                  ) : (
                    <BsFileEarmarkZip
                      className={`w-8 h-8 ${
                        isDragOver
                          ? "text-primary-500"
                          : "text-gray-400 dark:text-gray-500"
                      } transition-colors duration-300`}
                    />
                  )}
                </div>

                {/* Upload Text */}
                <h3 className="text-xl font-semibold text-white mb-2">
                  {isUploading ? "Processing..." : "Drop your APK file here"}
                </h3>
                <p className="text-gray-400 mb-4">
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
                  className="inline-flex items-center px-6 py-2.5 bg-gradient-to-r from-primary-600 to-teal-600 hover:from-primary-700 hover:to-teal-700 disabled:from-gray-400 disabled:to-gray-500 text-white font-medium rounded-xl shadow-lg hover:shadow-xl transform hover:-translate-y-1 disabled:transform-none transition-all duration-300"
                >
                  <HiUpload className="w-4 h-4 mr-2" />
                  {isUploading ? "Processing..." : "Browse Files"}
                </button>

                {/* File Requirements */}
                <div className="mt-6 p-3 rounded-lg bg-gray-800/50 border border-gray-700/50">
                  <h4 className="text-sm font-medium text-white mb-2">
                    File Requirements:
                  </h4>
                  <ul className="text-xs text-gray-400 space-y-1">
                    <li>• File format: .apk, .apks, .xapk</li>
                    <li>• Maximum size: 100MB</li>
                    <li>• Banking applications recommended</li>
                    <li>• No personal data is stored</li>
                  </ul>
                </div>
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
              <div className="mt-4 p-3 rounded-lg bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-700/50 animate-fade-in">
                <div className="flex items-center">
                  <HiExclamation className="w-4 h-4 text-danger-500 mr-2" />
                  <p className="text-sm text-danger-700 dark:text-danger-300 font-medium">
                    {uploadError}
                  </p>
                </div>
              </div>
            )}
          </div>
        ) : (
          /* File Preview */
          <div className="animate-fade-up">
            <div className="p-4 md:p-6 bg-gray-900 rounded-2xl border border-gray-700/50 shadow-lg">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white">
                  File Ready for Analysis
                </h3>
                <button
                  onClick={clearFile}
                  disabled={isAnalyzing}
                  className="p-2 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <HiX className="w-4 h-4" />
                </button>
              </div>

              {/* File Details */}
              <div className="flex items-center space-x-3 mb-4">
                <div className="flex-shrink-0">
                  <div className="w-10 h-10 bg-primary-100 dark:bg-primary-900/40 rounded-lg flex items-center justify-center">
                    <HiDocumentText className="w-5 h-5 text-primary-400" />
                  </div>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-base font-medium text-white truncate">
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
                className="w-full inline-flex items-center justify-center px-6 py-3 bg-gradient-to-r from-success-600 to-teal-600 hover:from-success-700 hover:to-teal-700 disabled:from-gray-400 disabled:to-gray-500 text-white font-semibold rounded-xl shadow-lg hover:shadow-xl transform hover:-translate-y-1 disabled:transform-none transition-all duration-300"
              >
                {isAnalyzing ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent mr-2"></div>
                    Analyzing APK...
                  </>
                ) : (
                  <>
                    <HiUpload className="w-4 h-4 mr-2" />
                    Start Security Analysis
                  </>
                )}
              </button>

              <p className="text-center text-xs text-gray-500 dark:text-gray-400 mt-3">
                {isAnalyzing
                  ? "Please wait while we analyze your APK file..."
                  : "Analysis typically takes 15-30 seconds"}
              </p>
            </div>
          </div>
        )}

        {/* Hidden File Input */}
        <input
          ref={fileInputRef}
          type="file"
          accept=".apk,.apks,.xapk"
          onChange={handleFileInputChange}
          className="hidden"
        />
      </div>
    </section>
  );
};

export default UploadSection;

