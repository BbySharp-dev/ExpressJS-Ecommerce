const { CONFIG_MESSAGE_ERRORS } = require("../configs");
const Review = require("../models/ReviewModel");
const { buildQuery, preparePaginationAndSorting } = require("../utils");
const mongoose = require("mongoose");

const createReview = (newReview) => {
  return new Promise(async (resolve, reject) => {
    const { content, star, product, user } = newReview;
    try {
      const newReview = await Review.create({
        content,
        star,
        product,
        user,
      });
      if (newReview) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
          message: "Review success",
          typeError: "",
          data: newReview,
          statusMessage: "Success",
        });
      }
    } catch (e) {
      reject(e);
    }
  });
};
const updateReview = (id, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkReview = await Review.findOne({
        _id: id,
      });
      if (checkReview === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The review is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }
      checkReview.content = data.content || checkReview.content;
      checkReview.star = data.star || checkReview.star;

      const saveReview = await checkReview.save();
     
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Updated review success",
        typeError: "",
        data: saveReview,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const updateReviewMine = (reviewId, userId, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkReview = await Review.findOne({
        _id: reviewId,
      });
      if (checkReview === null) {
        reject({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The review is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      } else if (userId !== checkReview?.user?.toString()) {
        reject({
          status: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.status,
          message: "Unauthorized",
          typeError: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.type,
          data: null,
          statusMessage: "Error",
        });
      }

      checkReview.content = data.content || checkReview.content;
      checkReview.star = data.star || checkReview.star;
      const saveReview = await checkReview.save();

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Updated review success",
        typeError: "",
        data: saveReview,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteReview = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkReview = await Review.findOne({
        _id: id,
      });
      if (checkReview === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The review is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }

      await Review.findByIdAndDelete(id);
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Deleted review success",
        typeError: "",
        data: checkReview,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteReviewMine = (reviewId, userId) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkReview = await Review.findOne({
        _id: reviewId,
      });
      if (checkReview === null) {
        reject({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The review is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      } else if (userId !== checkReview.user?.toString()) {
        reject({
          status: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.status,
          message: "Unauthorized",
          typeError: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.type,
          data: null,
          statusMessage: "Error",
        });
      }

      await Review.findByIdAndDelete(id);
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Deleted review success",
        typeError: "",
        data: checkReview,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteManyReview = (ids) => {
  return new Promise(async (resolve, reject) => {
    try {
      await Review.deleteMany({ _id: ids });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Delete reviews success",
        typeError: "",
        data: null,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getDetailsReview = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkReview = await Review.findOne({
        _id: id,
      });
      if (checkReview === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The review is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }
      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: checkReview,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getAllReview = (params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = +params?.limit ?? 10;
      const search = params?.search ?? "";
      const page = +params?.page ?? 1;
      const order = params?.order ?? "createdAt desc";
      const userId = params.userId ?? "";
      const productId = params.productId ?? "";
      const minStar = +params?.minStar || 0;
      const maxStar = +params?.maxStar || 5;

      const query = buildQuery(search);

      const { startIndex, sortOptions } = preparePaginationAndSorting(
        page,
        limit,
        order
      );

      if (userId) {
        const userIds = userId
          ?.split("|")
          .map((id) => mongoose.Types.ObjectId(id));
        query.user =
          userIds.length > 1
            ? { $in: userIds }
            : mongoose.Types.ObjectId(userId);
      }

      if (productId) {
        const productIds = productId
          ?.split("|")
          .map((id) => mongoose.Types.ObjectId(id));
        query.product =
          productIds.length > 1
            ? { $in: productIds }
            : mongoose.Types.ObjectId(productId);
      }

      if (minStar !== null || maxStar !== null) {
        query.star = {};
        if (minStar !== null) {
          query.star.$gte = minStar;
        }
        if (maxStar !== null) {
          query.star.$lte = maxStar;
        }
      }

      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [{ content: searchRegex }];
      }

      const totalCount = await Review.countDocuments(query);

      const totalPage = Math.ceil(totalCount / limit);

      const fieldsToSelect = {
        content: 1,
        star: 1,
        user: 1,
        product: 1,
        updatedAt: 1
      };
  
      if (page === -1 && limit === -1) {
        const allReview = await Review.find(query)
          .sort(sortOptions)
          .select(fieldsToSelect)
          .populate([
            {
              path: "user",
              select: "firstName lastName middleName _id avatar",
            },
            {
              path: "product",
              select: "name _id",
            },
          ]);

        resolve({
          status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
          message: "Success",
          typeError: "",
          statusMessage: "Success",
          data: {
            reviews: allReview,
            totalPage: 1,
            totalCount: totalCount,
          },
        });
        return;
      }

      const allReview = await Review.find(query)
        .skip(startIndex)
        .limit(limit)
        .sort(sortOptions)
        .select(fieldsToSelect)
        .populate([
          {
            path: "user",
            select: "firstName lastName middleName avatar _id",
          },
          {
            path: "product",
            select: "name _id",
          },
        ]);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        statusMessage: "Success",
        data: {
          reviews: allReview,
          totalPage: totalPage,
          totalCount: totalCount,
        },
      });
    } catch (e) {
      reject(e);
    }
  });
};

module.exports = {
  createReview,
  updateReview,
  getDetailsReview,
  deleteReview,
  getAllReview,
  deleteManyReview,
  updateReviewMine,
  deleteReviewMine,
};
