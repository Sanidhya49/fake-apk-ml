// Format file size in human readable format
export const formatFileSize = (bytes) => {
  if (bytes === 0) return "0 Bytes";

  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

// Format time duration
export const formatDuration = (milliseconds) => {
  const seconds = Math.floor(milliseconds / 1000);
  const minutes = Math.floor(seconds / 60);

  if (minutes > 0) {
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds}s`;
  }

  return `${seconds}s`;
};

// Validate file type
export const isValidAPKFile = (file) => {
  return file && file.name.toLowerCase().endsWith(".apk");
};

// Get file extension
export const getFileExtension = (filename) => {
  return filename.toLowerCase().split(".").pop();
};

// Truncate filename for display
export const truncateFilename = (filename, maxLength = 30) => {
  if (filename.length <= maxLength) return filename;

  const extension = getFileExtension(filename);
  const nameWithoutExt = filename.slice(0, filename.lastIndexOf("."));
  const truncateLength = maxLength - extension.length - 4; // Account for "..." and "."

  return `${nameWithoutExt.slice(0, truncateLength)}...${extension}`;
};

// Generate random delay for demo purposes
export const randomDelay = (min = 1000, max = 3000) => {
  return Math.floor(Math.random() * (max - min + 1)) + min;
};

// Debounce function
export const debounce = (func, wait) => {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
};

// Get risk color based on score
export const getRiskColor = (score) => {
  if (score >= 80) return "danger";
  if (score >= 60) return "warning";
  if (score >= 40) return "accent";
  return "success";
};

// Get verdict based on risk score
export const getVerdict = (score) => {
  if (score >= 70) return "dangerous";
  if (score >= 40) return "suspicious";
  return "safe";
};

// Get verdict color
export const getVerdictColor = (verdict) => {
  switch (verdict) {
    case "dangerous":
      return "text-danger-500";
    case "suspicious":
      return "text-warning-500";
    case "safe":
      return "text-success-500";
    default:
      return "text-gray-500";
  }
};

// Get verdict background
export const getVerdictBackground = (verdict) => {
  switch (verdict) {
    case "dangerous":
      return "bg-danger-500";
    case "suspicious":
      return "bg-warning-500";
    case "safe":
      return "bg-success-500";
    default:
      return "bg-gray-500";
  }
};

// Animate counter
export const animateCounter = (element, target, duration = 2000) => {
  if (!element) return;

  const start = 0;
  const range = target - start;
  const increment = target > start ? 1 : -1;
  const stepTime = Math.abs(Math.floor(duration / range));
  let current = start;

  const timer = setInterval(() => {
    current += increment;
    element.textContent = current;

    if (current === target) {
      clearInterval(timer);
    }
  }, stepTime);
};
