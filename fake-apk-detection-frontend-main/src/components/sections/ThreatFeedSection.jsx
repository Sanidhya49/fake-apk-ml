import React, { useEffect } from "react";
import { HiShieldCheck, HiClock, HiRefresh, HiDatabase, HiFingerPrint, HiGlobe } from "react-icons/hi";
import { HiExclamationTriangle } from "react-icons/hi2";
import { BsShieldFillCheck, BsShieldFillExclamation } from "react-icons/bs";
import useAppStore from "../../store/useAppStore";

const ThreatFeedSection = () => {
  const {
    threatFeedData,
    threatFeedError,
    isLoadingThreatFeed,
    loadThreatFeed,
  } = useAppStore();

  // Load threat feed data on component mount and set up auto-refresh
  useEffect(() => {
    loadThreatFeed();

    // Auto-refresh every 30 seconds
    const interval = setInterval(() => {
      loadThreatFeed();
    }, 30000);

    return () => clearInterval(interval);
  }, [loadThreatFeed]);

  const handleRefresh = () => {
    loadThreatFeed();
  };

  const formatLastUpdated = (timestamp) => {
    if (!timestamp || timestamp === 0) return "Never";
    return new Date(timestamp * 1000).toLocaleString();
  };

  return (
    <section
      id="threat-feed"
      className="py-8 md:py-12 bg-gray-50 dark:bg-gray-800 relative overflow-hidden"
    >
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-10">
        <div className="absolute inset-0 bg-grid-pattern"></div>
      </div>

      {/* Floating Elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 right-10 w-32 h-32 bg-gradient-to-br from-primary-400/15 to-teal-400/15 rounded-full blur-xl animate-float"></div>
        <div className="absolute bottom-20 left-10 w-24 h-24 bg-gradient-to-br from-teal-400/15 to-accent-400/15 rounded-full blur-xl animate-float-delayed"></div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Header */}
        <div className="text-center mb-8 animate-fade-up">
          <h2 className="text-2xl md:text-3xl lg:text-4xl font-bold text-gray-900 dark:text-white mb-3">
            <BsShieldFillCheck className="inline-block w-8 h-8 mr-3 text-primary-400" />
            Threat Intelligence
            <span className="block text-transparent bg-clip-text bg-gradient-to-r from-primary-400 to-teal-400">
              Dashboard
            </span>
          </h2>
          <p className="text-lg text-gray-600 dark:text-gray-300">
            Real-time threat intelligence feed protecting your devices from
            known malicious applications
          </p>
        </div>

        {/* Threat Feed Dashboard */}
        <div
          className="animate-fade-up bg-white dark:bg-gray-900 rounded-2xl shadow-xl border border-gray-200 dark:border-gray-700 overflow-hidden"
          style={{ animationDelay: "200ms" }}
        >
          {/* Header */}
          <div className="threat-feed-dashboard-header bg-gradient-to-r from-primary-600 via-teal-600 to-accent-600 p-6 text-white relative overflow-hidden">
            {/* Background pattern */}
            <div className="absolute inset-0 opacity-10">
              <div className="absolute inset-0 bg-grid-pattern"></div>
            </div>

            <div className="relative z-10 flex items-center justify-between">
              <div>
                <h3 className="text-xl md:text-2xl font-bold mb-2 flex items-center">
                  <HiShieldCheck className="w-6 h-6 mr-2" />
                  Threat Intelligence Feed
                </h3>
                <p className="text-white/90 text-sm md:text-base">
                  Live protection against known malicious applications
                </p>
              </div>

              <button
                onClick={handleRefresh}
                disabled={isLoadingThreatFeed}
                className={`p-3 rounded-lg bg-white/20 hover:bg-white/30 transition-all duration-200 ${
                  isLoadingThreatFeed
                    ? "animate-spin cursor-not-allowed"
                    : "hover:scale-105"
                }`}
                title="Refresh threat feed"
              >
                <HiRefresh className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Content */}
          <div className="p-6">
            {threatFeedError ? (
              <div className="text-center py-8">
                <HiExclamationTriangle className="w-12 h-12 text-warning-500 mx-auto mb-4" />
                <h4 className="text-lg font-semibold text-white mb-2">
                  Failed to Load Threat Feed
                </h4>
                <p className="text-gray-400 mb-4">{threatFeedError}</p>
                <button
                  onClick={handleRefresh}
                  className="inline-flex items-center px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white font-medium rounded-lg transition-colors"
                >
                  <HiRefresh className="w-4 h-4 mr-2" />
                  Try Again
                </button>
              </div>
            ) : isLoadingThreatFeed && !threatFeedData ? (
              <div className="text-center py-8">
                <div className="animate-spin w-8 h-8 border-4 border-primary-600 border-t-transparent rounded-full mx-auto mb-4"></div>
                <p className="text-gray-400">
                  Loading threat intelligence data...
                </p>
              </div>
            ) : threatFeedData ? (
              <>
                {/* Statistics Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                  {/* Known Bad Hashes */}
                  <div className="threat-feed-stat bg-gradient-to-br from-danger-900/20 to-danger-800/20 border border-danger-700/30 rounded-xl p-5 text-center transition-all duration-200 hover:scale-105 hover:shadow-lg">
                    <div className="inline-flex items-center justify-center w-12 h-12 bg-danger-500 text-white rounded-full mb-3">
                      <HiFingerPrint className="w-6 h-6" />
                    </div>
                    <div className="threat-feed-number text-2xl md:text-3xl font-bold text-danger-400 mb-1">
                      {threatFeedData.hash_count?.toLocaleString() || "0"}
                    </div>
                    <div className="threat-feed-label text-sm font-medium text-danger-300">
                      Known Bad Hashes
                    </div>
                  </div>

                  {/* Malicious Packages */}
                  <div className="threat-feed-stat bg-gradient-to-br from-warning-900/20 to-warning-800/20 border border-warning-700/30 rounded-xl p-5 text-center transition-all duration-200 hover:scale-105 hover:shadow-lg">
                    <div className="inline-flex items-center justify-center w-12 h-12 bg-warning-500 text-white rounded-full mb-3">
                      <HiDatabase className="w-6 h-6" />
                    </div>
                    <div className="threat-feed-number text-2xl md:text-3xl font-bold text-warning-400 mb-1">
                      {threatFeedData.package_count?.toLocaleString() || "0"}
                    </div>
                    <div className="threat-feed-label text-sm font-medium text-warning-300">
                      Malicious Packages
                    </div>
                  </div>

                  {/* Bad Certificates */}
                  <div className="threat-feed-stat bg-gradient-to-br from-accent-900/20 to-accent-800/20 border border-accent-700/30 rounded-xl p-5 text-center transition-all duration-200 hover:scale-105 hover:shadow-lg">
                    <div className="inline-flex items-center justify-center w-12 h-12 bg-accent-500 text-white rounded-full mb-3">
                      <HiGlobe className="w-6 h-6" />
                    </div>
                    <div className="threat-feed-number text-2xl md:text-3xl font-bold text-accent-400 mb-1">
                      {threatFeedData.cert_fingerprint_count?.toLocaleString() ||
                        "0"}
                    </div>
                    <div className="threat-feed-label text-sm font-medium text-accent-300">
                      Bad Certificates
                    </div>
                  </div>
                </div>

                {/* Last Updated */}
                <div className="threat-feed-updated bg-gray-800 rounded-lg p-4 text-center border border-gray-700">
                  <div className="flex items-center justify-center text-gray-400">
                    <HiClock className="w-4 h-4 mr-2" />
                    <span className="text-sm font-medium">
                      Last Updated:{" "}
                      {formatLastUpdated(threatFeedData.last_updated)}
                    </span>
                    {isLoadingThreatFeed && (
                      <div className="ml-2 animate-spin w-4 h-4 border-2 border-primary-600 border-t-transparent rounded-full"></div>
                    )}
                  </div>
                </div>

                {/* Protection Status */}
                <div className="mt-6 p-4 bg-gradient-to-r from-success-900/20 to-success-800/20 border border-success-700/30 rounded-lg">
                  <div className="flex items-center justify-center text-success-400">
                    <BsShieldFillCheck className="w-5 h-5 mr-2" />
                    <span className="font-medium">
                      Real-time Protection Active
                    </span>
                  </div>
                  <p className="text-center text-sm text-success-300 mt-1">
                    Your device is protected against all known threats in our
                    database
                  </p>
                </div>
              </>
            ) : (
              <div className="text-center py-8">
                <HiDatabase className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <h4 className="text-lg font-semibold text-white mb-2">
                  No Threat Data Available
                </h4>
                <p className="text-gray-400">
                  Threat intelligence feed data is currently unavailable.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
};

export default ThreatFeedSection;
