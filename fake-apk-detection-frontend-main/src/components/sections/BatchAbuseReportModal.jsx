import React, { useState } from "react";
import { HiX, HiShieldCheck, HiDocumentText } from "react-icons/hi";
import { HiExclamationTriangle } from "react-icons/hi2";
import useAppStore from "../../store/useAppStore";

const BatchAbuseReportModal = ({ isOpen, onClose, maliciousFiles, batchResults }) => {
  const [formData, setFormData] = useState({
    reporterEmail: "",
    reporterName: "",
    additionalNotes: "",
  });
  const [formErrors, setFormErrors] = useState({});
  const [evidenceBundle, setEvidenceBundle] = useState(null);
  const [reportSuccess, setReportSuccess] = useState(false);

  const { reportBatchAbuse, isReportingAbuse, abuseReportError } = useAppStore();

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));

    // Clear error when user starts typing
    if (formErrors[name]) {
      setFormErrors((prev) => ({
        ...prev,
        [name]: "",
      }));
    }
  };

  const validateForm = () => {
    const errors = {};

    if (!formData.reporterEmail.trim()) {
      errors.reporterEmail = "Email is required";
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.reporterEmail)) {
      errors.reporterEmail = "Please enter a valid email address";
    }

    if (!formData.reporterName.trim()) {
      errors.reporterName = "Name is required";
    }

    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    try {
      const result = await reportBatchAbuse(
        maliciousFiles,
        formData.reporterEmail.trim(),
        formData.reporterName.trim(),
        formData.additionalNotes.trim()
      );

      if (result.success) {
        setEvidenceBundle(result.evidenceBundle);
        setReportSuccess(true);
      }
    } catch (error) {
      console.error("Batch abuse report submission failed:", error);
    }
  };

  const handleClose = () => {
    if (!isReportingAbuse) {
      setFormData({
        reporterEmail: "",
        reporterName: "",
        additionalNotes: "",
      });
      setFormErrors({});
      setEvidenceBundle(null);
      setReportSuccess(false);
      onClose();
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  if (!isOpen) return null;

  const maliciousCount = batchResults ? batchResults.filter(r => r.prediction === "fake").length : 0;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="bg-white dark:bg-gray-900 rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-danger-100 dark:bg-danger-900/40 rounded-lg">
                <HiExclamationTriangle className="w-6 h-6 text-danger-600 dark:text-danger-400" />
              </div>
            <div>
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                Report Malicious APKs
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Submit evidence bundle for {maliciousCount} malicious APK{maliciousCount !== 1 ? 's' : ''}
              </p>
            </div>
          </div>
          <button
            onClick={handleClose}
            disabled={isReportingAbuse}
            className="p-2 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <HiX className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6">
          {!reportSuccess ? (
            <>
              {/* Malicious APKs Summary */}
              <div className="mb-6 p-4 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-700/50 rounded-lg">
                <h3 className="font-semibold text-danger-700 dark:text-danger-300 mb-2">
                  Malicious APKs Detected ({maliciousCount})
                </h3>
                <div className="space-y-2">
                  {batchResults
                    ?.filter(r => r.prediction === "fake")
                    .map((result, index) => (
                      <div key={index} className="flex items-center justify-between text-sm">
                        <span className="text-gray-700 dark:text-gray-300">
                          {result.file} - {result.app_label || 'Unknown App'}
                        </span>
                        <span className="px-2 py-1 bg-danger-100 dark:bg-danger-900/40 text-danger-700 dark:text-danger-300 rounded text-xs font-medium">
                          {Math.round(result.probability * 100)}% confidence
                        </span>
                      </div>
                    ))}
                </div>
              </div>

              {/* Form */}
              <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Your Email Address *
                  </label>
                  <input
                    type="email"
                    name="reporterEmail"
                    value={formData.reporterEmail}
                    onChange={handleInputChange}
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all duration-200 ${
                      formErrors.reporterEmail
                        ? "border-danger-300 dark:border-danger-600 bg-danger-50 dark:bg-danger-900/20"
                        : "border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800"
                    }`}
                    placeholder="your.email@example.com"
                    disabled={isReportingAbuse}
                  />
                  {formErrors.reporterEmail && (
                    <p className="mt-1 text-sm text-danger-600 dark:text-danger-400">
                      {formErrors.reporterEmail}
                    </p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Your Name *
                  </label>
                  <input
                    type="text"
                    name="reporterName"
                    value={formData.reporterName}
                    onChange={handleInputChange}
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all duration-200 ${
                      formErrors.reporterName
                        ? "border-danger-300 dark:border-danger-600 bg-danger-50 dark:bg-danger-900/20"
                        : "border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800"
                    }`}
                    placeholder="Your full name"
                    disabled={isReportingAbuse}
                  />
                  {formErrors.reporterName && (
                    <p className="mt-1 text-sm text-danger-600 dark:text-danger-400">
                      {formErrors.reporterName}
                    </p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Additional Notes
                  </label>
                  <textarea
                    name="additionalNotes"
                    value={formData.additionalNotes}
                    onChange={handleInputChange}
                    rows={4}
                    className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all duration-200"
                    placeholder="Any additional information about these malicious APKs..."
                    disabled={isReportingAbuse}
                  />
                </div>

                {/* Error Message */}
                {abuseReportError && (
                  <div className="p-4 rounded-lg bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-700/50">
                    <div className="flex items-center">
                      <HiExclamationTriangle className="w-5 h-5 text-danger-500 mr-3" />
                      <p className="text-danger-700 dark:text-danger-300 font-medium">
                        {abuseReportError}
                      </p>
                    </div>
                  </div>
                )}

                {/* Submit Button */}
                <div className="flex items-center justify-end space-x-3">
                  <button
                    type="button"
                    onClick={handleClose}
                    disabled={isReportingAbuse}
                    className="px-6 py-3 text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 font-medium transition-colors duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isReportingAbuse}
                    className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-danger-600 to-red-600 hover:from-danger-700 hover:to-red-700 disabled:from-gray-400 disabled:to-gray-500 text-white font-medium rounded-lg shadow-lg hover:shadow-xl transform hover:-translate-y-1 disabled:transform-none transition-all duration-300 disabled:cursor-not-allowed"
                  >
                    {isReportingAbuse ? (
                      <>
                        <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent mr-2"></div>
                        Submitting Report...
                      </>
                    ) : (
                      <>
                        <HiShieldCheck className="w-5 h-5 mr-2" />
                        Submit Evidence Bundle
                      </>
                    )}
                  </button>
                </div>
              </form>
            </>
          ) : (
            /* Success State */
            <div className="text-center py-8">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-success-100 dark:bg-success-900/40 rounded-full mb-4">
                <HiShieldCheck className="w-8 h-8 text-success-600 dark:text-success-400" />
              </div>
              <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
                Batch Abuse Report Submitted Successfully!
              </h3>
              <p className="text-gray-600 dark:text-gray-400 mb-6">
                Evidence bundles have been generated for {maliciousCount} malicious APK{maliciousCount !== 1 ? 's' : ''} and submitted to cybersecurity authorities.
              </p>

              {/* Evidence Bundle Info */}
              {evidenceBundle && (
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 mb-6">
                  <h4 className="font-semibold text-gray-900 dark:text-white mb-2">
                    Evidence Bundle Generated
                  </h4>
                  <div className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                    <p>• STIX 2.1 threat intelligence format</p>
                    <p>• Email templates for authorities</p>
                    <p>• Technical analysis reports</p>
                    <p>• Threat feed integration completed</p>
                  </div>
                </div>
              )}

              <button
                onClick={handleClose}
                className="inline-flex items-center px-6 py-3 bg-gradient-to-r from-primary-600 to-teal-600 hover:from-primary-700 hover:to-teal-700 text-white font-medium rounded-lg shadow-lg hover:shadow-xl transform hover:-translate-y-1 transition-all duration-300"
              >
                <HiDocumentText className="w-5 h-5 mr-2" />
                Close
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default BatchAbuseReportModal;
