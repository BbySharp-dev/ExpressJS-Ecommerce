const { CONFIG_PERMISSIONS } = require("../configs");
const fs = require("fs");
const BLACKLIST_FILE = "blacklist.json";
const dotenv = require("dotenv");
dotenv.config();

const validateRequiredInput = (data, arrRequired) => {
  const missingFields = arrRequired.filter(
    (field) => !JSON.stringify(data[field])
  );
  return missingFields;
};

const buildQuery = (search) => {
  const query = {};
  if (search) {
    const searchRegex = { $regex: search, $options: "i" };
    query.$or = [{ email: searchRegex }];
  }
  return query;
};

const preparePaginationAndSorting = (page, limit, order) => {
  const startIndex = (page - 1) * limit;
  const sortOptions = buildSortOptions(order);
  return { startIndex, sortOptions };
};

const buildSortOptions = (order) => {
  let sortOptions = {};
  if (order) {
    const orderFields = order
      .split(",")
      .map((field) => field.trim().split(" "));
    orderFields.forEach(([name, direction]) => {
      sortOptions[name] = direction.toLowerCase() === "asc" ? 1 : -1;
    });
  }
  return sortOptions;
};

const getAllPermissionValues = (permissions) => {
  const values = [];

  const collectValues = (obj) => {
    for (const key in obj) {
      if (typeof obj[key] === "object") {
        collectValues(obj[key]);
      } else {
        values.push(obj[key]);
      }
    }
  };

  collectValues(permissions);

  return values;
};

const hasPermission = (userPermissions, requiredPermission) => {
  return userPermissions.includes(requiredPermission);
};

const existedPermissionRole = (permission) => {
  const getAllValuePermission = getAllPermissionValues(CONFIG_PERMISSIONS);
  if (!Array.prototype.every) {
    Array.prototype.every = function (callback, thisArg) {
      for (var i = 0; i < this.length; i++) {
        if (!callback.call(thisArg, this[i], i, this)) {
          return false;
        }
      }
      return true;
    };
  }

  const isChecked = permission?.every(function (element) {
    return getAllValuePermission.includes(element);
  });
  return isChecked;
};

const parseTimeToMilliseconds = (timeString) => {
  const timeUnit = timeString.slice(-1);
  const timeValue = parseInt(timeString.slice(0, -1), 10);

  switch (timeUnit) {
    case "d":
      return timeValue * 24 * 60 * 60 * 1000;
    case "h":
      return timeValue * 60 * 60 * 1000;
    case "m":
      return timeValue * 60 * 1000;
    case "s":
      return timeValue * 1000;
    default:
      return 0;
  }
};

const getBlacklist = () => {
  try {
    const data = fs.readFileSync(BLACKLIST_FILE, "utf8");
    return JSON.parse(data);
  } catch (error) {
    return [];
  }
};

const addToBlacklist = async (token) => {
  try {
    const blacklist = getBlacklist();
    blacklist.push({
      token,
      expiry:
        Date.now() + parseTimeToMilliseconds(process.env.ACCESS_TOKEN_EXPIRE),
    });

    await new Promise((resolve, reject) => {
      fs.writeFile(BLACKLIST_FILE, JSON.stringify(blacklist), "utf8", (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  } catch (error) {
    throw error;
  }
};

const isTokenInBlacklist = (token) => {
  const blacklist = getBlacklist();
  const now = Date.now();
  return blacklist.some((item) => item.token === token && item.expiry > now);
};

const isAdminPermission = (permissions) => {
  if (permissions) {
    return permissions.includes(CONFIG_PERMISSIONS.ADMIN);
  }
  return false;
};

const validateDiscountDate = (discount, discountStartDate, discountEndDate) => {
  try{
    if (discount > 0) {
      if (!discountStartDate || !discountEndDate) {
        return {
          isValid: false,
          error: "Discount must have both start and end dates.",
        };
      }
  
      if (discountStartDate.getTime() < new Date().setHours(0, 0, 0, 0)) {
        return {
          isValid: false,
          error:
            "Discount start date should be greater than or equal to the current date.",
        };
      }
  
      if (discountEndDate.getTime() <= discountStartDate.getTime()) {
        return {
          isValid: false,
          error: "Discount end date should be greater than the start date.",
        };
      }
  
    }
  
    return { isValid: true, error: null };
  }catch (e) {
    return { isValid: false, error: e }
  }
};

const uniqueValuesArr = (array) => {
  return Array.from(new Set(array));
};

module.exports = {
  validateRequiredInput,
  buildQuery,
  preparePaginationAndSorting,
  buildSortOptions,
  getAllPermissionValues,
  hasPermission,
  existedPermissionRole,
  addToBlacklist,
  isTokenInBlacklist,
  isAdminPermission,
  validateDiscountDate,
  uniqueValuesArr
};
