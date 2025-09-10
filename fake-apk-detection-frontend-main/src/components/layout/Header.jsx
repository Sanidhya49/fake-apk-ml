import React from "react";
import { Link, useLocation } from "react-router-dom";
import { HiShieldCheck, HiUserCircle } from "react-icons/hi";
import { useAdminStore } from "../../store/useAdminStore";

const Header = () => {
  const location = useLocation();
  const { isAdmin } = useAdminStore();
  const isAdminRoute = location.pathname.startsWith("/admin");

  return (
    <header className="fixed top-0 left-0 right-0 z-50 bg-gray-900/90 backdrop-blur-md border-b border-gray-700/30">
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 md:h-20">
          <Link to="/" className="flex items-center space-x-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-teal-500 shadow-lg">
              <HiShieldCheck className="w-6 h-6 text-white" />
            </div>
            <div className="flex flex-col">
              <h1 className="text-xl md:text-2xl font-bold text-white">
                SecureAPK
                <span className="text-primary-400 ml-1">Detector</span>
              </h1>
              <p className="text-xs text-gray-400 hidden md:block">
                Digital Rakshak
              </p>
            </div>
          </Link>

          <div className="flex items-center space-x-4">
            {!isAdminRoute && (
              <Link
                to="/admin/login"
                className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 hover:text-white transition-colors duration-200"
              >
                <HiUserCircle className="w-5 h-5" />
                <span className="text-sm font-medium">Admin</span>
              </Link>
            )}

            {isAdmin && isAdminRoute && (
              <div className="flex items-center space-x-4">
                <Link
                  to="/admin/dashboard"
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-200 ${
                    location.pathname === "/admin/dashboard"
                      ? "bg-blue-600 text-white"
                      : "bg-gray-800 hover:bg-gray-700 text-gray-300 hover:text-white"
                  }`}
                >
                  Dashboard
                </Link>
                <Link
                  to="/"
                  className="px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 hover:text-white text-sm font-medium transition-colors duration-200"
                >
                  Home
                </Link>
              </div>
            )}
          </div>
        </div>
      </nav>
    </header>
  );
};

export default Header;
