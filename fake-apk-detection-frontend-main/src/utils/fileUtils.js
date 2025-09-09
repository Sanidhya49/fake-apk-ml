/**
 * Format file size in bytes to human readable format
 * @param {number} bytes - File size in bytes
 * @returns {string} Formatted file size
 */
export const formatFileSize = (bytes) => {
  if (bytes === 0) return "0 Bytes";

  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

/**
 * Validate APK file
 * @param {File} file - File object to validate
 * @returns {object} Validation result with isValid and error message
 */
export const validateAPKFile = (file) => {
  if (!file) {
    return { isValid: false, error: "No file selected" };
  }

  // Check file extension - support .apk, .apks, .xapk
  const fileName = file.name.toLowerCase();
  const validExtensions = [".apk", ".apks", ".xapk"];
  const hasValidExtension = validExtensions.some((ext) =>
    fileName.endsWith(ext)
  );

  if (!hasValidExtension) {
    return {
      isValid: false,
      error: "File must be an APK file (.apk, .apks, or .xapk)",
    };
  }

  // Check file size (100MB limit)
  const maxSize = 100 * 1024 * 1024; // 100MB in bytes
  if (file.size > maxSize) {
    return { isValid: false, error: "File size must be less than 100MB" };
  }

  // Check if file is empty
  if (file.size === 0) {
    return { isValid: false, error: "File cannot be empty" };
  }

  return { isValid: true, error: null };
};

/**
 * Get file type icon based on file name
 * @param {string} fileName - Name of the file
 * @returns {string} Icon class or emoji
 */
export const getFileTypeIcon = (fileName) => {
  if (!fileName) return "📄";

  const extension = fileName.toLowerCase().split(".").pop();

  switch (extension) {
    case "apk":
    case "apks":
    case "xapk":
      return "📱";
    case "pdf":
      return "📄";
    case "zip":
    case "rar":
      return "📦";
    case "jpg":
    case "jpeg":
    case "png":
    case "gif":
      return "🖼️";
    default:
      return "📄";
  }
};

/**
 * Generate unique file ID for tracking
 * @param {File} file - File object
 * @returns {string} Unique file identifier
 */
export const generateFileId = (file) => {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substr(2, 9);
  const nameHash = file.name.split("").reduce((a, b) => {
    a = (a << 5) - a + b.charCodeAt(0);
    return a & a;
  }, 0);

  return `${timestamp}-${nameHash}-${random}`;
};

/**
 * Create file preview data
 * @param {File} file - File object
 * @returns {object} File preview data
 */
export const createFilePreview = (file) => {
  return {
    id: generateFileId(file),
    name: file.name,
    size: file.size,
    type: file.type,
    lastModified: file.lastModified,
    formattedSize: formatFileSize(file.size),
    icon: getFileTypeIcon(file.name),
    uploadedAt: new Date().toISOString(),
  };
};
