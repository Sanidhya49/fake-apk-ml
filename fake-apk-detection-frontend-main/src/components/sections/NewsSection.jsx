import React, { useState, useEffect } from "react";
import { HiNewspaper, HiShieldCheck, HiAcademicCap, HiChartBar } from "react-icons/hi";
import { HiExclamationTriangle } from "react-icons/hi2";
import { APKAnalysisService } from "../../services/api";

const NewsSection = () => {
  const [newsData, setNewsData] = useState(null);
  const [categories, setCategories] = useState(null);
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [enhancedMode, setEnhancedMode] = useState(false);
  const [systemInfo, setSystemInfo] = useState(null);

  useEffect(() => {
    loadNewsData();
  }, []);

  const loadNewsData = async (enhanced = false) => {
    try {
      setIsLoading(true);
      setError(null);

      const [newsResponse, categoriesResponse] = await Promise.all([
        APKAnalysisService.getNews(enhanced),
        APKAnalysisService.getNewsCategories()
      ]);

      setNewsData(newsResponse.data);
      setCategories(categoriesResponse.data);
      setSystemInfo(newsResponse.data);
      setEnhancedMode(enhanced);
    } catch (error) {
      console.error("Failed to load news data:", error);
      setError("Failed to load news and security updates");
    } finally {
      setIsLoading(false);
    }
  };

  const toggleEnhancedMode = async () => {
    const newEnhancedMode = !enhancedMode;
    await loadNewsData(newEnhancedMode);
  };

  const getCategoryIcon = (category) => {
    switch (category) {
      case "guidelines":
        return <HiShieldCheck className="w-5 h-5" />;
      case "alert":
        return <HiExclamationTriangle className="w-5 h-5" />;
      case "education":
        return <HiAcademicCap className="w-5 h-5" />;
      case "intelligence":
        return <HiChartBar className="w-5 h-5" />;
      default:
        return <HiNewspaper className="w-5 h-5" />;
    }
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case "critical":
        return "text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-900/20";
      case "high":
        return "text-orange-600 dark:text-orange-400 bg-orange-100 dark:bg-orange-900/20";
      case "medium":
        return "text-yellow-600 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-900/20";
      default:
        return "text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-900/20";
    }
  };

  const getThreatLevelColor = (level) => {
    switch (level) {
      case "High":
        return "text-red-600 dark:text-red-400";
      case "Medium":
        return "text-yellow-600 dark:text-yellow-400";
      case "Low":
        return "text-green-600 dark:text-green-400";
      default:
        return "text-gray-600 dark:text-gray-400";
    }
  };

  const formatContent = (content) => {
    return content.split('\n').map((line, index) => (
      <React.Fragment key={index}>
        {line}
        {index < content.split('\n').length - 1 && <br />}
      </React.Fragment>
    ));
  };

  const getAllNewsItems = () => {
    if (!newsData) return [];
    
    const allItems = [];
    Object.entries(newsData.news).forEach(([category, items]) => {
      items.forEach(item => {
        allItems.push({ ...item, category });
      });
    });
    
    return allItems.sort((a, b) => new Date(b.date) - new Date(a.date));
  };

  const getFilteredNewsItems = () => {
    const allItems = getAllNewsItems();
    
    if (selectedCategory === "all") {
      return allItems;
    }
    
    return allItems.filter(item => item.category === selectedCategory);
  };

  if (isLoading) {
    return (
      <section className="py-12 bg-gray-50 dark:bg-gray-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto"></div>
            <p className="mt-4 text-gray-600 dark:text-gray-400">Loading security updates...</p>
          </div>
        </div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="py-12 bg-gray-50 dark:bg-gray-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center">
          <HiExclamationTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-red-600 dark:text-red-400">{error}</p>
            <button
              onClick={loadNewsData}
              className="mt-4 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </section>
    );
  }

  const filteredItems = getFilteredNewsItems();

  return (
    <section className="py-12 bg-gray-50 dark:bg-gray-900">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <HiNewspaper className="w-8 h-8 text-primary-600 dark:text-primary-400 mr-3" />
            <h2 className="text-3xl font-bold text-gray-900 dark:text-white">
              Security News & Awareness
            </h2>
          </div>
          <p className="text-lg text-gray-600 dark:text-gray-400 max-w-3xl mx-auto mb-6">
            Stay informed about the latest banking security threats, RBI guidelines, and best practices to protect yourself from fake banking apps.
          </p>
          
          {/* Enhanced Mode Toggle */}
          <div className="flex items-center justify-center space-x-4">
            <button
              onClick={toggleEnhancedMode}
              className={`inline-flex items-center px-4 py-2 rounded-lg font-medium transition-all duration-200 ${
                enhancedMode
                  ? "bg-gradient-to-r from-purple-600 to-blue-600 text-white shadow-lg"
                  : "bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 border border-gray-300 dark:border-gray-600"
              }`}
            >
              <HiChartBar className="w-4 h-4 mr-2" />
              {enhancedMode ? "AI Enhanced Mode" : "Enable AI Enhancement"}
            </button>
            
            {systemInfo && (
              <div className="text-sm text-gray-500 dark:text-gray-400">
                {/* {systemInfo.source === "hybrid" && (
                  <span className="inline-flex items-center px-2 py-1 bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-300 rounded-full">
                    🔄 Hybrid Mode
                  </span>
                )} */}
                {systemInfo.threat_feed_connected && (
                  <span className="inline-flex items-center px-2 py-1 bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300 rounded-full ml-2">
                    📡 Live Data
                  </span>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Category Filter */}
        {categories && (
          <div className="flex flex-wrap justify-center gap-3 mb-8">
            <button
              onClick={() => setSelectedCategory("all")}
              className={`px-4 py-2 rounded-lg font-medium transition-all duration-200 ${
                selectedCategory === "all"
                  ? "bg-primary-600 text-white shadow-lg"
                  : "bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
              }`}
            >
              All ({getAllNewsItems().length})
            </button>
            {Object.entries(categories.categories).map(([key, category]) => (
              <button
                key={key}
                onClick={() => setSelectedCategory(key)}
                className={`px-4 py-2 rounded-lg font-medium transition-all duration-200 flex items-center ${
                  selectedCategory === key
                    ? "bg-primary-600 text-white shadow-lg"
                    : "bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                }`}
              >
                <span className="mr-2">{category.icon}</span>
                {category.name} ({category.count})
              </button>
            ))}
          </div>
        )}

        {/* News Items */}
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {filteredItems.map((item) => (
            <div
              key={item.id}
              className="bg-white dark:bg-gray-800 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 overflow-hidden"
            >
              {/* Header */}
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center">
                    <div className="p-2 bg-primary-100 dark:bg-primary-900/40 rounded-lg mr-3">
                      {getCategoryIcon(item.category)}
                    </div>
                    <div>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getPriorityColor(item.priority)}`}>
                        {item.priority.toUpperCase()}
                      </span>
                    </div>
                  </div>
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    {new Date(item.date).toLocaleDateString()}
                  </span>
                </div>
                
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                  {item.title}
                </h3>
                
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Source: {item.source}
                </p>
              </div>

              {/* Content */}
              <div className="p-6">
                <div className="text-gray-700 dark:text-gray-300 leading-relaxed">
                  {formatContent(item.content)}
                </div>

                {/* Additional Info */}
                {item.affected_banks && (
                  <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                    <p className="text-sm font-medium text-yellow-800 dark:text-yellow-200 mb-1">
                      Affected Banks:
                    </p>
                    <div className="flex flex-wrap gap-1">
                      {item.affected_banks.map((bank, index) => (
                        <span
                          key={index}
                          className="px-2 py-1 bg-yellow-200 dark:bg-yellow-800 text-yellow-800 dark:text-yellow-200 rounded text-xs"
                        >
                          {bank}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {item.threat_level && (
                  <div className="mt-3 flex items-center">
                    <span className="text-sm font-medium text-gray-600 dark:text-gray-400 mr-2">
                      Threat Level:
                    </span>
                    <span className={`font-semibold ${getThreatLevelColor(item.threat_level)}`}>
                      {item.threat_level}
                    </span>
                  </div>
                )}

                {item.statistics && (
                  <div className="mt-4 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                    <p className="text-sm font-medium text-blue-800 dark:text-blue-200 mb-2">
                      Statistics:
                    </p>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div>
                        <span className="text-blue-600 dark:text-blue-400">Apps Detected:</span>
                        <span className="ml-1 font-semibold">{item.statistics.fake_apps_detected}</span>
                      </div>
                      <div>
                        <span className="text-blue-600 dark:text-blue-400">Accuracy:</span>
                        <span className="ml-1 font-semibold">{item.statistics.detection_accuracy}</span>
                      </div>
                    </div>
                    {item.statistics.common_permissions && (
                      <div className="mt-2">
                        <span className="text-blue-600 dark:text-blue-400 text-xs">Common Permissions:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {item.statistics.common_permissions.map((perm, index) => (
                            <span
                              key={index}
                              className="px-1 py-0.5 bg-blue-200 dark:bg-blue-800 text-blue-800 dark:text-blue-200 rounded text-xs"
                            >
                              {perm}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Empty State */}
        {filteredItems.length === 0 && (
          <div className="text-center py-12">
            <HiNewspaper className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              No news items found
            </h3>
            <p className="text-gray-600 dark:text-gray-400">
              Try selecting a different category or check back later for updates.
            </p>
          </div>
        )}

        {/* Last Updated */}
        {newsData && (
          <div className="text-center mt-8">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Last updated: {new Date(newsData.last_updated).toLocaleString()}
            </p>
          </div>
        )}
      </div>
    </section>
  );
};

export default NewsSection;
