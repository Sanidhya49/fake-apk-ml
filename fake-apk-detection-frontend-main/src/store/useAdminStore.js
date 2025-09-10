import { create } from "zustand";
import { persist } from "zustand/middleware";
import { APKAnalysisService } from "../services/api";

export const useAdminStore = create(
  persist(
    (set, get) => ({
      isAdmin: false,
      adminToken: null,
      adminUser: null,
      setIsAdmin: (value) => set({ isAdmin: value }),
      setAdminToken: (token) => set({ adminToken: token }),
      setAdminUser: (user) => set({ adminUser: user }),
      logout: () => set({ isAdmin: false, adminToken: null, adminUser: null }),

      // Reports state
      reports: [],
      stats: {
        total: 0,
        batch: 0,
        single: 0,
        high_risk: 0,
        medium_risk: 0,
        low_risk: 0,
      },
      pagination: {
        page: 1,
        per_page: 20,
        total: 0,
        pages: 0,
      },
      loading: false,
      error: null,
      selectedReport: null,

      // Admin API functions
      fetchReports: async (page = 1, perPage = 20) => {
        set({ loading: true, error: null });
        try {
          const response = await APKAnalysisService.getAdminReports(
            page,
            perPage
          );
          const data = response.data;

          set({
            reports: data.reports || [],
            stats: data.stats || get().stats,
            pagination: data.pagination || get().pagination,
            loading: false,
          });

          return data;
        } catch (error) {
          console.error("Error fetching reports:", error);
          set({
            error: error.message || "Failed to fetch reports",
            loading: false,
          });
          throw error;
        }
      },

      fetchSingleReport: async (reportId) => {
        set({ loading: true, error: null });
        try {
          const response = await APKAnalysisService.getSingleReport(reportId);
          const data = response.data;

          set({
            selectedReport: data,
            loading: false,
          });

          return data;
        } catch (error) {
          console.error("Error fetching single report:", error);
          set({
            error: error.message || "Failed to fetch report",
            loading: false,
          });
          throw error;
        }
      },

      deleteReport: async (reportId) => {
        set({ loading: true, error: null });
        try {
          const response = await APKAnalysisService.deleteReport(reportId);
          const data = response.data;

          // Remove the deleted report from the current reports list
          const currentReports = get().reports;
          const updatedReports = currentReports.filter(
            (report) => !report.file_metadata?.filename?.startsWith(reportId)
          );

          set({
            reports: updatedReports,
            loading: false,
          });

          // Refresh the reports list to get updated stats
          await get().fetchReports(
            get().pagination.page,
            get().pagination.per_page
          );

          return data;
        } catch (error) {
          console.error("Error deleting report:", error);
          set({
            error: error.message || "Failed to delete report",
            loading: false,
          });
          throw error;
        }
      },

      // Utility functions
      clearError: () => set({ error: null }),
      clearSelectedReport: () => set({ selectedReport: null }),

      // Get formatted timestamp
      formatTimestamp: (timestamp) => {
        try {
          const date = new Date(timestamp * 1000); // Convert from Unix timestamp
          return date.toLocaleString();
        } catch (error) {
          console.error("Error formatting timestamp:", error);
          return "Invalid Date";
        }
      },

      // Get risk level color
      getRiskLevelColor: (riskLevel) => {
        switch (riskLevel) {
          case "Red":
            return "text-red-600 bg-red-100";
          case "Amber":
            return "text-orange-600 bg-orange-100";
          case "Yellow":
            return "text-yellow-600 bg-yellow-100";
          case "Green":
            return "text-green-600 bg-green-100";
          default:
            return "text-gray-600 bg-gray-100";
        }
      },

      // Get report type badge
      getReportTypeBadge: (reportType) => {
        switch (reportType) {
          case "batch":
            return "bg-blue-100 text-blue-800";
          case "single":
            return "bg-green-100 text-green-800";
          default:
            return "bg-gray-100 text-gray-800";
        }
      },
    }),
    {
      name: "admin-storage", // Storage key name
      partialize: (state) => ({
        isAdmin: state.isAdmin,
        adminToken: state.adminToken,
        adminUser: state.adminUser,
      }),
    }
  )
);
