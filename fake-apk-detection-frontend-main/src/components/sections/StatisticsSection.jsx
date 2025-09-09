import React from "react";
import {
  HiUpload,
  HiCheckCircle,
  HiClock,
  HiShieldCheck,
  HiExclamation,
  HiCreditCard,
} from "react-icons/hi";
import { BsShieldFillCheck } from "react-icons/bs";

const StatisticsSection = () => {
  return (
    <section
      id="statistics"
      className="py-16 md:py-24 bg-gray-900 relative overflow-hidden"
    >
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-2">
        <div className="absolute inset-0 bg-grid-pattern"></div>
      </div>
    </section>
  );
};

export default StatisticsSection;
