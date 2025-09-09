import React from "react";
import { HiCube, HiPlay } from "react-icons/hi";
import { BsRobot, BsShieldFillCheck } from "react-icons/bs";
const AboutSection = () => {
  const howItWorks = [
    {
      step: 1,
      title: "Upload APK",
      description:
        "Securely upload your banking APK file through our encrypted interface",
      icon: HiCube,
      color: "from-teal-500 to-teal-600",
    },
    {
      step: 2,
      title: "AI Analysis",
      description:
        "Advanced machine learning models analyze code patterns and behavior",
      icon: BsRobot,
      color: "from-teal-500 to-teal-600",
    },
    {
      step: 3,
      title: "Security Scan",
      description:
        "Comprehensive security checks including signatures and permissions",
      icon: BsShieldFillCheck,
      color: "from-teal-500 to-teal-600",
    },
    {
      step: 4,
      title: "Results",
      description:
        "Get detailed security report with recommendations and risk assessment",
      icon: HiPlay,
      color: "from-teal-500 to-teal-600",
    },
  ];

  return (
    <section
      id="about"
      className="py-16 md:py-24 bg-gray-50 dark:bg-gray-800 relative overflow-hidden"
    >
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-2">
        <div className="absolute inset-0 bg-grid-pattern"></div>
      </div>

      {/* Floating Elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 left-10 w-32 h-32 bg-gradient-to-br from-primary-400/10 to-teal-400/10 rounded-full blur-xl animate-float"></div>
        <div
          className="absolute bottom-20 right-10 w-40 h-40 bg-gradient-to-br from-accent-400/10 to-success-400/10 rounded-full blur-xl animate-float"
          style={{ animationDelay: "2s" }}
        ></div>
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* How It Works */}
        <div className="">
          <div
            className="text-center mb-24 animate-fade-up"
            style={{ animationDelay: "300ms" }}
          >
            <h3 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4">
              How It Works
            </h3>
            <p className="text-xl text-gray-300">
              Four simple steps to comprehensive security analysis
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {howItWorks.map((item, index) => (
              <div
                key={index}
                className="text-center animate-fade-up"
                style={{ animationDelay: `${400 + index * 100}ms` }}
              >
                <div className="relative mb-6">
                  <div className="absolute -top-2 left-0 w-8 h-8 bg-gray-900 dark:bg-white text-white dark:text-gray-900 rounded-full flex items-center justify-center text-sm font-bold">
                    {item.step}
                  </div>
                  <div
                    className={`inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-r ${item.color} shadow-lg mb-4`}
                  >
                    <item.icon className="w-10 h-10 text-white" />
                  </div>
                </div>
                <h4 className="text-xl font-bold text-gray-900 dark:text-white mb-2">
                  {item.title}
                </h4>
                <p className="text-gray-400 leading-relaxed">
                  {item.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default AboutSection;

