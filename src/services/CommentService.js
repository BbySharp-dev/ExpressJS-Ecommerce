const { CONFIG_MESSAGE_ERRORS, ACTION_SOCKET_COMMENT } = require("../configs");
const Comment = require("../models/CommentModel");
const { buildQuery, preparePaginationAndSorting } = require("../utils");
const mongoose = require("mongoose");
const socketModule = require("../socket");

const createComment = (newComment) => {
  return new Promise(async (resolve, reject) => {
    const { content, product, user } = newComment;
    try {
      const socketIo = socketModule.getIo();
      const newComment = await Comment.create({
        content,
        product,
        user,
        parent: null,
        replies: [],
      });

      const fieldsToSelect = {
        content: 1,
        product: 1,
        user: 1,
        replies: 1,
        user: {
          id: "$userInfo._id",
          firstName: "$userInfo.firstName",
          middleName: "$userInfo.middleName",
          lastName: "$userInfo.lastName",
          avatar: "$userInfo.avatar",
        },
        product: {
          id: "$productInfo._id",
          firstName: "$productInfo.name",
        },
        createdAt: 1,
      };
      const formatComment = await Comment.aggregate([
        { $match: { _id: newComment._id } },
        {
          $lookup: {
            from: "users",
            localField: "user",
            foreignField: "_id",
            as: "userInfo",
          },
        },
        {
          $unwind: "$userInfo",
        },
        {
          $lookup: {
            from: "products",
            localField: "product",
            foreignField: "_id",
            as: "productInfo",
          },
        },
        {
          $unwind: "$productInfo",
        },
        {
          $project: fieldsToSelect,
        },
      ]);
      socketIo.emit(ACTION_SOCKET_COMMENT.CREATE_COMMENT, formatComment[0]);
      if (newComment) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
          message: "Comment success",
          typeError: "",
          data: newComment,
          statusMessage: "Success",
        });
      }
    } catch (e) {
      reject(e);
    }
  });
};

const replyComment = (newComment) => {
  return new Promise(async (resolve, reject) => {
    const { content, product, user, parent } = newComment;
    try {
      const newReply = await Comment.create({
        content,
        product,
        user,
        parent: parent,
        replies: [],
      });
      const socketIo = socketModule.getIo();

      const parentComment = await Comment.findById(parent);
      if (parentComment) {
        parentComment.replies.push(newReply._id);
        await parentComment.save();
      }

      const fieldsToSelect = {
        content: 1,
        product: 1,
        parent: 1,
        user: 1,
        user: {
          id: "$userInfo._id",
          firstName: "$userInfo.firstName",
          middleName: "$userInfo.middleName",
          lastName: "$userInfo.lastName",
          avatar: "$userInfo.avatar",
        },
        product: {
          id: "$productInfo._id",
          firstName: "$productInfo.name",
        },
        createdAt: 1,
      };
      const formatReply = await Comment.aggregate([
        { $match: { _id: newReply._id } },
        {
          $lookup: {
            from: "users",
            localField: "user",
            foreignField: "_id",
            as: "userInfo",
          },
        },
        {
          $unwind: "$userInfo",
        },
        {
          $lookup: {
            from: "products",
            localField: "product",
            foreignField: "_id",
            as: "productInfo",
          },
        },
        {
          $unwind: "$productInfo",
        },
        {
          $project: fieldsToSelect,
        },
      ]);

      socketIo.emit(ACTION_SOCKET_COMMENT.REPLY_COMMENT, formatReply[0]);

      if (newReply) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
          message: "Reply success",
          typeError: "",
          data: newReply,
          statusMessage: "Success",
        });
      }
    } catch (e) {
      reject(e);
    }
  });
};

const updateComment = (id, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const socketIo = socketModule.getIo();
      const checkComment = await Comment.findOne({
        _id: id,
      });
      if (checkComment === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The comment is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }
      checkComment.content = data.content || checkComment.content;
      const fieldsToSelect = {
        content: 1,
        product: 1,
        parent: 1,
        user: 1,
        replies: 1,
        user: {
          id: "$userInfo._id",
          firstName: "$userInfo.firstName",
          middleName: "$userInfo.middleName",
          lastName: "$userInfo.lastName",
          avatar: "$userInfo.avatar",
        },
        product: {
          id: "$productInfo._id",
          firstName: "$productInfo.name",
        },
        createdAt: 1,
      };

      const saveComment = await checkComment.save();

      const formatComment = await Comment.aggregate([
        { $match: { _id: checkComment._id } },
        {
          $lookup: {
            from: "users",
            localField: "user",
            foreignField: "_id",
            as: "userInfo",
          },
        },
        {
          $unwind: "$userInfo",
        },
        {
          $lookup: {
            from: "products",
            localField: "product",
            foreignField: "_id",
            as: "productInfo",
          },
        },
        {
          $unwind: "$userInfo",
        },
        {
          $project: fieldsToSelect,
        },
      ]);

      socketIo.emit(ACTION_SOCKET_COMMENT.UPDATE_COMMENT, formatComment[0]);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Updated comment success",
        typeError: "",
        data: saveComment,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const updateMyComment = (commentId, userId, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const socketIo = socketModule.getIo();
      const checkComment = await Comment.findOne({
        _id: commentId,
      });
      if (checkComment === null) {
        reject({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The comment is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      } else if (userId !== checkComment?.user?.toString()) {
        reject({
          status: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.status,
          message: "Unauthorized",
          typeError: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.type,
          data: null,
          statusMessage: "Error",
        });
      }

      checkComment.content = data.content || checkComment.content;

      const fieldsToSelect = {
        content: 1,
        product: 1,
        parent: 1,
        user: 1,
        user: {
          id: "$userInfo._id",
          firstName: "$userInfo.firstName",
          middleName: "$userInfo.middleName",
          lastName: "$userInfo.lastName",
          avatar: "$userInfo.avatar",
        },
        createdAt: 1,
      };

      const saveComment = await checkComment.save();

      const formatComment = await Comment.aggregate([
        { $match: { _id: checkComment._id } },
        {
          $lookup: {
            from: "users",
            localField: "user",
            foreignField: "_id",
            as: "userInfo",
          },
        },
        {
          $unwind: "$userInfo",
        },
        {
          $project: fieldsToSelect,
        },
      ]);

      socketIo.emit(ACTION_SOCKET_COMMENT.UPDATE_COMMENT, formatComment[0]);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Updated comment success",
        typeError: "",
        data: saveComment,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteComment = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const socketIo = socketModule.getIo();
      const checkComment = await Comment.findOne({
        _id: id,
      });
      if (checkComment === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The comment is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }

      if (!checkComment.parent) {
        // Nếu là comment cha, xóa cả comment và các reply liên quan
        await Comment.deleteMany({ $or: [{ _id: id }, { parent: id }] });
      } else {
        // Nếu là reply, chỉ xóa reply đó
        await Comment.findByIdAndDelete(id);
      }

      socketIo.emit(ACTION_SOCKET_COMMENT.DELETE_COMMENT, checkComment);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Deleted comment success",
        typeError: "",
        data: checkComment,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteMyComment = (commentId, userId) => {
  return new Promise(async (resolve, reject) => {
    try {
      const socketIo = socketModule.getIo();
      const checkComment = await Comment.findOne({
        _id: commentId,
      });
      if (checkComment === null) {
        reject({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The comment is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      } else if (userId !== checkComment.user?.toString()) {
        reject({
          status: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.status,
          message: "Unauthorized",
          typeError: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.type,
          data: null,
          statusMessage: "Error",
        });
      }

      if (!checkComment.parent) {
        // Nếu là comment cha, xóa cả comment và các reply liên quan
        await Comment.deleteMany({
          $or: [{ _id: commentId }, { parent: commentId }],
        });
      } else {
        // Nếu là reply, chỉ xóa reply đó
        await Comment.findByIdAndDelete(commentId);
      }

      socketIo.emit(ACTION_SOCKET_COMMENT.DELETE_COMMENT, checkComment);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Deleted comment success",
        typeError: "",
        data: checkComment,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteManyComment = (ids) => {
  return new Promise(async (resolve, reject) => {
    try {
      const socketIo = socketModule.getIo();
      const childComments = await Comment.find({ parent: { $in: ids } });
      const childCommentIds = childComments.map((comment) => comment._id);
      // Xóa các bình luận con
      await Comment.deleteMany({ _id: { $in: childCommentIds } });

      await Comment.deleteMany({ _id: { $in: ids } });
      socketIo.emit(ACTION_SOCKET_COMMENT.DELETE_MULTIPLE_COMMENT, ids);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Delete comments success",
        typeError: "",
        data: null,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getDetailsComment = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const fieldsToSelect = {
        content: 1,
        product: 1,
        product: {
          id: "$productInfo._id",
          name: "$productInfo.name",
        },
        user: 1,
        user: {
          id: "$userInfo._id",
          firstName: "$userInfo.firstName",
          middleName: "$userInfo.middleName",
          lastName: "$userInfo.lastName",
        },
        replies: 1,
        replies: {
          $map: {
            input: "$replies",
            as: "reply",
            in: {
              id: "$$reply._id",
              content: "$$reply.content",
              product: {
                id: "$repliesProductInfo._id",
                name: "$repliesProductInfo.name",
              },
              user: {
                id: "$repliesUserInfo._id",
                firstName: "$repliesUserInfo.firstName",
                middleName: "$repliesUserInfo.middleName",
                lastName: "$repliesUserInfo.lastName",
              },
            },
          },
        },
      };

      const checkComment = await Comment.aggregate([
        { $match: { _id: mongoose.Types.ObjectId(id) } },
        {
          $lookup: {
            from: "users",
            localField: "user",
            foreignField: "_id",
            as: "userInfo",
          },
        },
        {
          $unwind: "$userInfo",
        },
        {
          $lookup: {
            from: "products",
            localField: "product",
            foreignField: "_id",
            as: "productInfo",
          },
        },
        {
          $unwind: "$productInfo",
        },
        {
          $lookup: {
            from: "comments",
            localField: "_id",
            foreignField: "parent",
            as: "replies",
          },
        },
        {
          $lookup: {
            from: "users",
            localField: "user",
            foreignField: "_id",
            as: "repliesUserInfo",
          },
        },
        {
          $unwind: "$repliesUserInfo",
        },
        {
          $lookup: {
            from: "products",
            localField: "product",
            foreignField: "_id",
            as: "repliesProductInfo",
          },
        },
        {
          $unwind: "$repliesProductInfo",
        },
        {
          $project: fieldsToSelect,
        },
      ]);

      if (checkComment[0] === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The comment is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }

      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: checkComment[0],
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getAllComment = (params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = +params?.limit ?? 10;
      const search = params?.search ?? "";
      const page = +params?.page ?? 1;
      const order = params?.order ?? "createdAt desc";
      const userId = params.userId ?? "";
      const productId = params.productId ?? "";
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
        query.type =
          userIds.length > 1
            ? { $in: userIds }
            : mongoose.Types.ObjectId(userId);
      }

      if (productId) {
        const productIds = productId
          ?.split("|")
          .map((id) => mongoose.Types.ObjectId(id));
        query.type =
          productIds.length > 1
            ? { $in: productIds }
            : mongoose.Types.ObjectId(productId);
      }

      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [{ content: searchRegex }];
      }

      const totalCount = await Comment.countDocuments(query);

      const totalPage = Math.ceil(totalCount / limit);

      const fieldsToSelect = {
        content: 1,
        product: 1,
        parent: 1,
        user: 1,
      };

      if (page === -1 && limit === -1) {
        const allComment = await Comment.find(query)
          .sort(sortOptions)
          .populate([
            {
              path: "user",
              select: "_id firstName lastName middleName",
            },
            {
              path: "product",
              select: "name _id",
            },
          ])
          .select(fieldsToSelect);

        resolve({
          status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
          message: "Success",
          typeError: "",
          statusMessage: "Success",
          data: {
            comments: allComment,
            totalPage: 1,
            totalCount: totalCount,
          },
        });
        return;
      }

      const allComment = await Comment.find(query)
        .skip(startIndex)
        .limit(limit)
        .sort(sortOptions)
        .populate([
          {
            path: "user",
            select: "_id firstName lastName middleName",
          },
          {
            path: "product",
            select: "name _id",
          },
        ])
        .select(fieldsToSelect);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        statusMessage: "Success",
        data: {
          comments: allComment,
          totalPage: totalPage,
          totalCount: totalCount,
        },
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getAllCommentPublic = (params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = +params?.limit ?? 10;
      const search = params?.search ?? "";
      const page = +params?.page ?? 1;
      const order = params?.order ?? "createdAt desc";
      const userId = params.userId ?? "";
      const productId = params.productId ?? "";
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

      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [{ content: searchRegex }];
      }

      const totalCount = await Comment.countDocuments(query);

      query.parent = null;

      const totalPage = Math.ceil(totalCount / limit);

      const fieldsToSelect = {
        content: 1,
        product: 1,
        product: {
          id: "$productInfo._id",
          name: "$productInfo.name",
        },
        createdAt: 1,
        user: {
          id: "$userInfo._id",
          firstName: "$userInfo.firstName",
          lastName: "$userInfo.lastName",
          avatar: "$userInfo.avatar",
        },
        replies: {
          $ifNull: ["$replies", []],
        },
        replies: {
          $map: {
            input: "$replies",
            as: "reply",
            in: {
              _id: "$$reply._id",
              parent: "$$reply.parent",
              content: "$$reply.content",
              createdAt: "$$reply.createdAt",
              user: {
                id: "$repliesUserInfo._id",
                firstName: "$repliesUserInfo.firstName",
                lastName: "$repliesUserInfo.lastName",
                avatar: "$repliesUserInfo.avatar",
              },
              product: {
                id: "$repliesProductInfo._id",
                name: "$repliesProductInfo.name",
              },
            },
          },
        },
      };

      if (page === -1 && limit === -1) {
        const pipeline = [
          { $match: query },
          { $sort: sortOptions },
          {
            $lookup: {
              from: "users",
              localField: "user",
              foreignField: "_id",
              as: "userInfo",
            },
          },
          {
            $unwind: "$userInfo",
          },
          {
            $lookup: {
              from: "products",
              localField: "product",
              foreignField: "_id",
              as: "productInfo",
            },
          },
          {
            $unwind: "$productInfo",
          },
          {
            $project: fieldsToSelect,
          },
        ];

        const allComment = await Comment.aggregate(pipeline);

        const commentIds = allComment.map((comment) => comment._id);
        const replies = await Comment.aggregate([
          { $match: { parent: { $in: commentIds } } },
          {
            $lookup: {
              from: "users",
              localField: "user",
              foreignField: "_id",
              as: "repliesUserInfo",
            },
          },
          {
            $unwind: "$repliesUserInfo",
          },
          {
            $lookup: {
              from: "products",
              localField: "product",
              foreignField: "_id",
              as: "repliesProductInfo",
            },
          },
          {
            $unwind: "$repliesProductInfo",
          },
          {
            $project: {
              _id: 1,
              parent: 1,
              content: 1,
              createdAt: 1,
              user: {
                id: "$repliesUserInfo._id",
                firstName: "$repliesUserInfo.firstName",
                lastName: "$repliesUserInfo.lastName",
              },
              product: {
                id: "$repliesProductInfo._id",
                name: "$repliesProductInfo.name",
              },
            },
          },
        ]);

        allComment.forEach((comment) => {
          comment.replies = replies.filter((reply) =>
            reply?.parent?.equals(comment._id)
          );
        });

        resolve({
          status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
          message: "Success",
          typeError: "",
          statusMessage: "Success",
          data: {
            comments: allComment,
            totalPage: 1,
            totalCount: totalCount,
          },
        });
        return;
      }

      const allComment = await Comment.aggregate([
        { $match: query },
        { $sort: sortOptions },
        { $skip: startIndex },
        { $limit: limit },
        {
          $lookup: {
            from: "users",
            localField: "user",
            foreignField: "_id",
            as: "userInfo",
          },
        },
        {
          $unwind: "$userInfo",
        },
        {
          $lookup: {
            from: "products",
            localField: "product",
            foreignField: "_id",
            as: "productInfo",
          },
        },
        {
          $unwind: "$productInfo",
        },
        {
          $lookup: {
            from: "comments",
            localField: "_id",
            foreignField: "parent",
            as: "replies",
          },
        },
        {
          $lookup: {
            from: "users",
            localField: "user",
            foreignField: "_id",
            as: "repliesUserInfo",
          },
        },
        {
          $unwind: "$repliesUserInfo",
        },
        {
          $lookup: {
            from: "products",
            localField: "product",
            foreignField: "_id",
            as: "repliesProductInfo",
          },
        },
        {
          $unwind: "$repliesProductInfo",
        },
        {
          $project: fieldsToSelect,
        },
      ]);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        statusMessage: "Success",
        data: {
          comments: allComment,
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
  createComment,
  updateComment,
  getDetailsComment,
  deleteComment,
  getAllComment,
  deleteManyComment,
  updateMyComment,
  deleteMyComment,
  replyComment,
  getAllCommentPublic,
};
