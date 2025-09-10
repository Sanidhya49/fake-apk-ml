import React, { useState } from "react";
import {
  HiX,
  HiCheckCircle,
  HiMail,
  HiUser,
  HiDocumentText,
  HiUpload,
  HiShieldExclamation,
} from "react-icons/hi";
import { HiExclamationTriangle } from "react-icons/hi2";
import { BsFileEarmarkZip, BsShieldFillExclamation } from "react-icons/bs";
import useAppStore from "../../store/useAppStore";
import { validateAPKFile } from "../../utils/fileUtils";

const AbuseReportModal = ({ isOpen, onClose, preFilledFile = null }) => {
  const {
    isReportingAbuse,
    abuseReportError,
    reportAbuse,
    setAbuseReportError,
  } = useAppStore();

  const [formData, setFormData] = useState({
    file: preFilledFile,
    reporterEmail: "",
    reporterName: "",
    additionalNotes: "",
  });

  const [evidenceBundle, setEvidenceBundle] = useState(null);
  const [reportSuccess, setReportSuccess] = useState(false);
  const [formErrors, setFormErrors] = useState({});

  const handleInputChange = (field, value) => {
    setFormData((prev) => ({ ...prev, [field]: value }));

    // Clear specific field error when user starts typing
    if (formErrors[field]) {
      setFormErrors((prev) => ({ ...prev, [field]: null }));
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      const validation = validateAPKFile(file);
      if (validation.isValid) {
        handleInputChange("file", file);
      } else {
        setFormErrors((prev) => ({ ...prev, file: validation.error }));
      }
    }
  };

  const validateForm = () => {
    const errors = {};

    if (!formData.file) {
      errors.file = "Please select an APK file to report";
    }

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

    setAbuseReportError(null);

    try {
      const result = await reportAbuse(
        formData.file,
        formData.reporterEmail.trim(),
        formData.reporterName.trim(),
        formData.additionalNotes.trim()
      );

      if (result.success) {
        setEvidenceBundle(result.evidenceBundle);
        setReportSuccess(true);
      }
    } catch (error) {
      console.error("Abuse report submission failed:", error);
    }
  };

  const handleClose = () => {
    if (!isReportingAbuse) {
      setFormData({
        file: null,
        reporterEmail: "",
        reporterName: "",
        additionalNotes: "",
      });
      setFormErrors({});
      setEvidenceBundle(null);
      setReportSuccess(false);
      setAbuseReportError(null);
      onClose();
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="bg-white dark:bg-gray-900 rounded-2xl shadow-2xl border border-gray-700 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-700 bg-gradient-to-r from-danger-50 to-warning-50 dark:from-danger-900/20 dark:to-warning-900/20">
          <div className="flex items-center">
            <BsShieldFillExclamation className="w-6 h-6 text-danger-600 dark:text-danger-400 mr-3" />
            <h3 className="text-xl font-bold text-gray-900 dark:text-white">
              Report Malicious APK
            </h3>
          </div>
          <button
            onClick={handleClose}
            disabled={isReportingAbuse}
            className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
          >
            <HiX className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6">
          {reportSuccess && evidenceBundle ? (
            /* Success State */
            <div className="text-center">
              <div className="w-16 h-16 bg-success-100 dark:bg-success-900/20 rounded-full flex items-center justify-center mx-auto mb-4">
                <HiCheckCircle className="w-8 h-8 text-success-600 dark:text-success-400" />
              </div>

              <h4 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
                Report Submitted Successfully
              </h4>

              <p className="text-gray-400 mb-6">
                Your abuse report has been submitted and evidence bundle
                generated.
              </p>

              {/* Evidence Bundle Details */}
              <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 mb-6 text-left">
                <h5 className="font-semibold text-gray-900 dark:text-white mb-3">
                  Evidence Bundle Generated:
                </h5>

                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">
                      Report ID:
                    </span>
                    <code className="bg-gray-200 dark:bg-gray-700 px-2 py-1 rounded text-xs">
                      {evidenceBundle.report_metadata?.report_id}
                    </code>
                  </div>

                  <div className="flex justify-between">
                    <span className="text-gray-400">
                      APK SHA-256:
                    </span>
                    <button
                      onClick={() =>
                        copyToClipboard(evidenceBundle.apk_analysis?.sha256)
                      }
                      className="bg-gray-200 dark:bg-gray-700 px-2 py-1 rounded text-xs hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors font-mono"
                      title="Click to copy"
                    >
                      {evidenceBundle.apk_analysis?.sha256?.substring(0, 16)}...
                    </button>
                  </div>

                  <div className="flex justify-between">
                    <span className="text-gray-400">
                      Risk Level:
                    </span>
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium ${
                        evidenceBundle.apk_analysis?.risk_level === "Red"
                          ? "bg-danger-100 text-danger-700 dark:bg-danger-900/20 dark:text-danger-400"
                          : "bg-warning-100 text-warning-700 dark:bg-warning-900/20 dark:text-warning-400"
                      }`}
                    >
                      {evidenceBundle.apk_analysis?.risk_level} Risk
                    </span>
                  </div>
                </div>
              </div>

              {/* STIX Pattern */}
              {evidenceBundle.stix_template && (
                <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4 mb-6 text-left">
                  <h5 className="font-semibold text-gray-900 dark:text-white mb-2">
                    STIX Indicator Pattern:
                  </h5>
                  <code className="block bg-white dark:bg-gray-800 p-3 rounded border text-xs font-mono break-all">
                    {evidenceBundle.stix_template.pattern}
                  </code>
                </div>
              )}

              <button
                onClick={handleClose}
                className="w-full px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white font-medium rounded-lg transition-colors"
              >
                Close
              </button>
            </div>
          ) : (
            /* Form State */
            <>
              <div className="bg-warning-50 dark:bg-warning-900/20 border border-warning-200 dark:border-warning-700/30 rounded-lg p-4 mb-6">
                <div className="flex items-start">
                  <HiExclamationTriangle className="w-5 h-5 text-warning-600 dark:text-warning-400 mr-3 mt-0.5 flex-shrink-0" />
                  <div>
                    <h4 className="font-medium text-warning-800 dark:text-warning-300 mb-1">
                      Report Malicious APK
                    </h4>
                    <p className="text-sm text-warning-700 dark:text-warning-400">
                      Help protect the community by reporting malicious
                      applications. This will generate a comprehensive evidence
                      bundle and add the threat to our intelligence feed.
                    </p>
                  </div>
                </div>
              </div>

              <form onSubmit={handleSubmit} className="space-y-6">
                {/* APK File Upload */}
                <div className="abuse-report-form-group">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    <HiUpload className="inline w-4 h-4 mr-1" />
                    APK File *
                  </label>

                  {formData.file ? (
                    <div className="flex items-center p-3 bg-gray-50 dark:bg-gray-800 border border-gray-700 rounded-lg">
                      <BsFileEarmarkZip className="w-5 h-5 text-primary-400 mr-3" />
                      <span className="text-sm text-gray-900 dark:text-white flex-1">
                        {formData.file.name}
                      </span>
                      {!preFilledFile && (
                        <button
                          type="button"
                          onClick={() => handleInputChange("file", null)}
                          className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                        >
                          <HiX className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  ) : (
                    <input
                      type="file"
                      accept=".apk,.apks,.xapk"
                      onChange={handleFileChange}
                      className="abuse-report-form-input w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                    />
                  )}

                  {formErrors.file && (
                    <p className="mt-1 text-sm text-danger-600 dark:text-danger-400">
                      {formErrors.file}
                    </p>
                  )}
                </div>

                {/* Reporter Email */}
                <div className="abuse-report-form-group">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    <HiMail className="inline w-4 h-4 mr-1" />
                    Your Email *
                  </label>
                  <input
                    type="email"
                    value={formData.reporterEmail}
                    onChange={(e) =>
                      handleInputChange("reporterEmail", e.target.value)
                    }
                    placeholder="reporter@example.com"
                    className="abuse-report-form-input w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                  />
                  {formErrors.reporterEmail && (
                    <p className="mt-1 text-sm text-danger-600 dark:text-danger-400">
                      {formErrors.reporterEmail}
                    </p>
                  )}
                </div>

                {/* Reporter Name */}
                <div className="abuse-report-form-group">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    <HiUser className="inline w-4 h-4 mr-1" />
                    Your Name *
                  </label>
                  <input
                    type="text"
                    value={formData.reporterName}
                    onChange={(e) =>
                      handleInputChange("reporterName", e.target.value)
                    }
                    placeholder="Your full name"
                    className="abuse-report-form-input w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                  />
                  {formErrors.reporterName && (
                    <p className="mt-1 text-sm text-danger-600 dark:text-danger-400">
                      {formErrors.reporterName}
                    </p>
                  )}
                </div>

                {/* Additional Notes */}
                <div className="abuse-report-form-group">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    <HiDocumentText className="inline w-4 h-4 mr-1" />
                    Additional Notes
                  </label>
                  <textarea
                    value={formData.additionalNotes}
                    onChange={(e) =>
                      handleInputChange("additionalNotes", e.target.value)
                    }
                    placeholder="Describe how you encountered this malicious APK, any observed behavior, or additional context..."
                    rows={3}
                    className="abuse-report-form-input w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                  />
                </div>

                {/* Error Display */}
                {abuseReportError && (
                  <div className="p-4 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-700/30 rounded-lg">
                    <div className="flex items-start">
                      <HiShieldExclamation className="w-5 h-5 text-danger-600 dark:text-danger-400 mr-3 mt-0.5 flex-shrink-0" />
                      <div>
                        <h4 className="font-medium text-danger-800 dark:text-danger-300 mb-1">
                          Report Submission Failed
                        </h4>
                        <p className="text-sm text-danger-700 dark:text-danger-400">
                          {abuseReportError}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Action Buttons */}
                <div className="flex gap-3 pt-4">
                  <button
                    type="button"
                    onClick={handleClose}
                    disabled={isReportingAbuse}
                    className="flex-1 px-4 py-2 border border-gray-400 dark:border-gray-500 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 font-medium rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Cancel
                  </button>

                  <button
                    type="submit"
                    disabled={isReportingAbuse}
                    className="flex-1 px-4 py-2 border border-danger-400 dark:border-danger-500 bg-danger-100 dark:bg-danger-800 text-danger-700 dark:text-danger-300 font-medium rounded-lg hover:bg-danger-200 dark:hover:bg-danger-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
                  >
                    {isReportingAbuse ? (
                      <>
                        <div className="animate-spin w-4 h-4 border-2 border-danger-600 dark:border-danger-400 border-t-transparent rounded-full mr-2"></div>
                        Submitting Report...
                      </>
                    ) : (
                      <>
                        <HiShieldExclamation className="w-4 h-4 mr-2" />
                        Submit Abuse Report
                      </>
                    )}
                  </button>
                </div>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default AbuseReportModal;

