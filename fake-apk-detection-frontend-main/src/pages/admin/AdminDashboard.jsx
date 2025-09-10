import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAdminStore } from "../../store/useAdminStore";

const AdminDashboard = () => {
  const {
    reports,
    stats,
    pagination,
    loading,
    error,
    selectedReport,
    adminUser,
    fetchReports,
    fetchSingleReport,
    deleteReport,
    clearError,
    clearSelectedReport,
    logout,
    formatTimestamp,
    getRiskLevelColor,
    getReportTypeBadge,
  } = useAdminStore();

  const navigate = useNavigate();

  const [showModal, setShowModal] = useState(false);
  const [reportToDelete, setReportToDelete] = useState(null);

  useEffect(() => {
    const loadReports = async () => {
      try {
        await fetchReports();
      } catch (error) {
        console.error("Failed to fetch reports:", error);
      }
    };

    loadReports();
  }, [fetchReports]);

  const handlePageChange = (newPage) => {
    fetchReports(newPage, pagination.per_page);
  };

  const handleViewReport = async (reportId) => {
    try {
      await fetchSingleReport(reportId);
      setShowModal(true);
    } catch (error) {
      console.error("Failed to fetch report details:", error);
    }
  };

  const handleDeleteReport = async (reportId) => {
    try {
      await deleteReport(reportId);
      setReportToDelete(null);
    } catch (error) {
      console.error("Failed to delete report:", error);
    }
  };

  const closeModal = () => {
    setShowModal(false);
    clearSelectedReport();
  };

  const handleLogout = () => {
    logout();
    navigate("/admin/login");
  };

  if (loading && reports.length === 0) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto"></div>
          <p className="mt-4 text-gray-300">Loading reports...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8 flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold text-white">Admin Dashboard</h1>
            <p className="mt-2 text-gray-300">
              Monitor and manage abuse reports
              {adminUser && (
                <span className="ml-2 text-sm text-primary-400">
                  • Logged in as {adminUser.username}
                </span>
              )}
            </p>
          </div>
          <button
            onClick={handleLogout}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md transition-colors duration-200 flex items-center space-x-2"
          >
            <svg
              className="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
              />
            </svg>
            <span>Logout</span>
          </button>
        </div>

        {/* Error Message */}
        {error && (
          <div className="mb-6 bg-red-900/50 border border-red-600/50 rounded-md p-4 backdrop-blur-sm">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg
                  className="h-5 w-5 text-red-400"
                  viewBox="0 0 20 20"
                  fill="currentColor"
                >
                  <path
                    fillRule="evenodd"
                    d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                    clipRule="evenodd"
                  />
                </svg>
              </div>
              <div className="ml-3">
                <p className="text-sm text-red-300">{error}</p>
                <button
                  onClick={clearError}
                  className="mt-1 text-sm text-red-400 underline hover:text-red-300"
                >
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
          <div className="bg-gray-800/90 backdrop-blur-sm border border-gray-700/50 rounded-lg shadow-xl p-6">
            <h3 className="text-sm font-medium text-gray-400">Total Reports</h3>
            <p className="text-2xl font-bold text-white">{stats.total}</p>
          </div>
          <div className="bg-gray-800/90 backdrop-blur-sm border border-gray-700/50 rounded-lg shadow-xl p-6">
            <h3 className="text-sm font-medium text-gray-400">
              Single Reports
            </h3>
            <p className="text-2xl font-bold text-blue-400">{stats.single}</p>
          </div>
          <div className="bg-gray-800/90 backdrop-blur-sm border border-gray-700/50 rounded-lg shadow-xl p-6">
            <h3 className="text-sm font-medium text-gray-400">Batch Reports</h3>
            <p className="text-2xl font-bold text-purple-400">{stats.batch}</p>
          </div>
          <div className="bg-gray-800/90 backdrop-blur-sm border border-gray-700/50 rounded-lg shadow-xl p-6">
            <h3 className="text-sm font-medium text-gray-400">High Risk</h3>
            <p className="text-2xl font-bold text-red-400">{stats.high_risk}</p>
          </div>
          <div className="bg-gray-800/90 backdrop-blur-sm border border-gray-700/50 rounded-lg shadow-xl p-6">
            <h3 className="text-sm font-medium text-gray-400">Medium Risk</h3>
            <p className="text-2xl font-bold text-orange-400">
              {stats.medium_risk}
            </p>
          </div>
          <div className="bg-gray-800/90 backdrop-blur-sm border border-gray-700/50 rounded-lg shadow-xl p-6">
            <h3 className="text-sm font-medium text-gray-400">Low Risk</h3>
            <p className="text-2xl font-bold text-yellow-400">
              {stats.low_risk}
            </p>
          </div>
        </div>

        {/* Reports Table */}
        <div className="bg-gray-800/90 backdrop-blur-sm border border-gray-700/50 shadow-xl rounded-lg">
          <div className="px-6 py-4 border-b border-gray-700/50">
            <h2 className="text-lg font-medium text-white">Recent Reports</h2>
          </div>

          {reports.length === 0 ? (
            <div className="text-center py-12">
              <svg
                className="mx-auto h-12 w-12 text-gray-500"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                />
              </svg>
              <h3 className="mt-2 text-sm font-medium text-white">
                No reports found
              </h3>
              <p className="mt-1 text-sm text-gray-400">
                No abuse reports have been submitted yet.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-700/50">
                <thead className="bg-gray-700/50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Report ID
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Type
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      APK File
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Risk Level
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Reporter
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Timestamp
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-gray-800/50 divide-y divide-gray-700/50">
                  {reports.map((report) => (
                    <tr
                      key={report.file_metadata?.filename || Math.random()}
                      className="hover:bg-gray-700/50 transition-colors duration-200"
                    >
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-200">
                        {report.report_metadata?.report_id || "N/A"}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getReportTypeBadge(
                            report.report_type
                          )}`}
                        >
                          {report.report_type || "Unknown"}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-200">
                        {report.apk_analysis?.filename || "N/A"}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getRiskLevelColor(
                            report.apk_analysis?.risk_level
                          )}`}
                        >
                          {report.apk_analysis?.risk_level || "Unknown"}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-200">
                        <div>
                          <div className="font-medium text-white">
                            {report.report_metadata?.reporter?.name ||
                              "Anonymous"}
                          </div>
                          <div className="text-gray-400">
                            {report.report_metadata?.reporter?.email || "N/A"}
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                        {formatTimestamp(report.report_metadata?.timestamp)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
                        <button
                          onClick={() =>
                            handleViewReport(report.report_metadata?.report_id)
                          }
                          className="text-blue-400 hover:text-blue-300 transition-colors duration-200"
                        >
                          View
                        </button>
                        <button
                          onClick={() =>
                            setReportToDelete(report.report_metadata?.report_id)
                          }
                          className="text-red-400 hover:text-red-300 transition-colors duration-200"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination */}
          {pagination.pages > 1 && (
            <div className="px-6 py-4 border-t border-gray-700/50 flex items-center justify-between">
              <div className="text-sm text-gray-300">
                Showing page {pagination.page} of {pagination.pages} (
                {pagination.total} total reports)
              </div>
              <div className="flex space-x-2">
                <button
                  onClick={() => handlePageChange(pagination.page - 1)}
                  disabled={pagination.page === 1 || loading}
                  className="px-3 py-1 border border-gray-600 rounded-md text-sm text-gray-200 hover:bg-gray-700/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
                >
                  Previous
                </button>
                <button
                  onClick={() => handlePageChange(pagination.page + 1)}
                  disabled={pagination.page === pagination.pages || loading}
                  className="px-3 py-1 border border-gray-600 rounded-md text-sm text-gray-200 hover:bg-gray-700/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Report Detail Modal */}
      {showModal && selectedReport && (
        <div className="fixed inset-0 bg-gray-900/80 backdrop-blur-sm overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border border-gray-700/50 w-11/12 max-w-4xl shadow-2xl rounded-lg bg-gray-800/95 backdrop-blur-sm">
            <div className="mt-3">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-bold text-white">
                  Report Details: {selectedReport.report_metadata?.report_id}
                </h3>
                <button
                  onClick={closeModal}
                  className="text-gray-400 hover:text-gray-200 transition-colors duration-200"
                >
                  <svg
                    className="h-6 w-6"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M6 18L18 6M6 6l12 12"
                    />
                  </svg>
                </button>
              </div>

              <div className="max-h-96 overflow-y-auto">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* APK Analysis */}
                  <div className="bg-gray-700/50 border border-gray-600/50 p-4 rounded-lg">
                    <h4 className="font-medium text-white mb-2">
                      APK Analysis
                    </h4>
                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="font-medium text-gray-300">
                          Filename:
                        </span>{" "}
                        <span className="text-gray-200">
                          {selectedReport.apk_analysis?.filename}
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-300">
                          Package:
                        </span>{" "}
                        <span className="text-gray-200">
                          {selectedReport.apk_analysis?.package || "N/A"}
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-300">
                          SHA256:
                        </span>{" "}
                        <span className="font-mono text-xs text-gray-200">
                          {selectedReport.apk_analysis?.sha256 || "N/A"}
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-300">
                          Prediction:
                        </span>{" "}
                        <span className="text-gray-200">
                          {selectedReport.apk_analysis?.prediction}
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-300">
                          Probability:
                        </span>{" "}
                        <span className="text-gray-200">
                          {(
                            selectedReport.apk_analysis?.probability * 100
                          ).toFixed(2)}
                          %
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-300">
                          Risk Level:
                        </span>
                        <span
                          className={`ml-2 inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getRiskLevelColor(
                            selectedReport.apk_analysis?.risk_level
                          )}`}
                        >
                          {selectedReport.apk_analysis?.risk_level}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Reporter Info */}
                  <div className="bg-gray-700/50 border border-gray-600/50 p-4 rounded-lg">
                    <h4 className="font-medium text-white mb-2">
                      Reporter Information
                    </h4>
                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="font-medium text-gray-300">Name:</span>{" "}
                        <span className="text-gray-200">
                          {selectedReport.report_metadata?.reporter?.name}
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-300">
                          Email:
                        </span>{" "}
                        <span className="text-gray-200">
                          {selectedReport.report_metadata?.reporter?.email}
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-300">
                          Timestamp:
                        </span>{" "}
                        <span className="text-gray-200">
                          {formatTimestamp(
                            selectedReport.report_metadata?.timestamp
                          )}
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-300">
                          Notes:
                        </span>{" "}
                        <span className="text-gray-200">
                          {selectedReport.report_metadata?.additional_notes ||
                            "None"}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Technical Indicators */}
                  <div className="bg-gray-700/50 border border-gray-600/50 p-4 rounded-lg">
                    <h4 className="font-medium text-white mb-2">
                      Technical Indicators
                    </h4>
                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="font-medium text-gray-300">
                          Permissions:
                        </span>{" "}
                        <span className="text-gray-200">
                          {selectedReport.technical_indicators?.permissions
                            ?.length || 0}
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-300">
                          Suspicious APIs:
                        </span>{" "}
                        <span className="text-gray-200">
                          {
                            Object.keys(
                              selectedReport.technical_indicators
                                ?.suspicious_apis || {}
                            ).length
                          }
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-300">
                          Certificate:
                        </span>{" "}
                        <span className="text-gray-200">
                          {
                            selectedReport.technical_indicators
                              ?.certificate_info?.status
                          }
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* STIX Template */}
                  <div className="bg-gray-700/50 border border-gray-600/50 p-4 rounded-lg">
                    <h4 className="font-medium text-white mb-2">
                      STIX Template
                    </h4>
                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="font-medium text-gray-300">Type:</span>{" "}
                        <span className="text-gray-200">
                          {selectedReport.stix_template?.type}
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-300">
                          Labels:
                        </span>{" "}
                        <span className="text-gray-200">
                          {selectedReport.stix_template?.labels?.join(", ")}
                        </span>
                      </div>
                      <div>
                        <span className="font-medium text-gray-300">
                          Pattern:
                        </span>{" "}
                        <span className="font-mono text-xs text-gray-200">
                          {selectedReport.stix_template?.pattern}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={closeModal}
                  className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-md transition-colors duration-200"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {reportToDelete && (
        <div className="fixed inset-0 bg-gray-900/80 backdrop-blur-sm overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border border-gray-700/50 w-96 shadow-2xl rounded-lg bg-gray-800/95 backdrop-blur-sm">
            <div className="mt-3 text-center">
              <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-900/50 border border-red-600/50">
                <svg
                  className="h-6 w-6 text-red-400"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.962-.833-2.732 0L3.082 16.5c-.77.833.192 2.5 1.732 2.5z"
                  />
                </svg>
              </div>
              <h3 className="text-lg font-medium text-white mt-2">
                Delete Report
              </h3>
              <div className="mt-2 px-7 py-3">
                <p className="text-sm text-gray-300">
                  Are you sure you want to delete this report? This action
                  cannot be undone.
                </p>
              </div>
              <div className="flex justify-center space-x-3 mt-4">
                <button
                  onClick={() => setReportToDelete(null)}
                  className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-md transition-colors duration-200"
                >
                  Cancel
                </button>
                <button
                  onClick={() => handleDeleteReport(reportToDelete)}
                  className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md transition-colors duration-200"
                  disabled={loading}
                >
                  {loading ? "Deleting..." : "Delete"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminDashboard;
