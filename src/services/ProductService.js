const { CONFIG_MESSAGE_ERRORS } = require("../configs");
const Product = require("../models/ProductModel");
const User = require("../models/UserModel");
const mongoose = require("mongoose");

const createProduct = (newProduct) => {
  return new Promise(async (resolve, reject) => {
    const {
      name,
      image,
      type,
      countInStock,
      price,
      rating,
      description,
      discount,
      slug,
      status,
      location,
    } = newProduct;
    try {
      const discountStartDate =
        newProduct.discountStartDate && discount
          ? newProduct.discountStartDate
          : null;
      const discountEndDate =
        newProduct.discountEndDate && discount
          ? newProduct.discountEndDate
          : null;
      const checkProduct = await Product.findOne({
        slug: slug,
      });
      if (checkProduct !== null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
          message: "The product name is existed",
          typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
          data: null,
          statusMessage: "Error",
        });
      }
      const dataCreate = {
        name,
        image,
        type,
        countInStock: Number(countInStock),
        price,
        rating,
        description,
        discount: Number(discount),
        slug: slug,
        discountStartDate,
        discountEndDate,
        status,
      };
      if (location) {
        dataCreate.location = location;
      }
      const createdProduct = await Product.create(dataCreate);
      if (createdProduct) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
          message: "Created product success",
          typeError: "",
          data: createdProduct,
          statusMessage: "Success",
        });
      }
    } catch (e) {
      reject(e);
    }
  });
};

const updateProduct = (id, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkProduct = await Product.findOne({
        _id: id,
      });

      if (!checkProduct) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The product is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }

      if (data.slug && data.slug !== checkProduct.slug) {
        const existedName = await Product.findOne({
          slug: data.slug,
          _id: { $ne: id },
        });

        if (existedName !== null) {
          resolve({
            status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
            message: "The slug of product is existed",
            typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
            data: null,
            statusMessage: "Error",
          });
          return;
        }
      }
      const dataCreate = data;
      if (data.location) {
        dataCreate.location = data.location;
      }

      const updatedProduct = await Product.findByIdAndUpdate(id, dataCreate, {
        new: true,
      });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Updated product success",
        typeError: "",
        data: updatedProduct,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteProduct = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkProduct = await Product.findOne({
        _id: id,
      });
      if (checkProduct === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The product is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }

      await Product.findByIdAndDelete(id);
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Deleted product success",
        typeError: "",
        data: checkProduct,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteManyProduct = (ids) => {
  return new Promise(async (resolve, reject) => {
    try {
      await Product.deleteMany({ _id: ids });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Delete products success",
        typeError: "",
        data: null,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getDetailsProduct = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkProduct = await Product.findOne({
        _id: id,
      });
      if (checkProduct === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The product is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }
      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: checkProduct,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getDetailsProductPublic = (productId, userId, params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const isViewed = params.isViewed ?? false;
      const checkProduct = await Product.findOne({
        _id: productId,
        status: 1,
      });
      if (checkProduct === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The product is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }
      if (isViewed) {
        const user = await User.findById(userId);

        if (user) {
          const viewedProductsStrings = user.viewedProducts.map((id) =>
            id.toString()
          );
          if (!viewedProductsStrings.includes(productId)) {
            user.viewedProducts.push(productId);

            // if (user.viewedProducts.length > 10) {
            //   user.viewedProducts.shift();
            // }

            await user.save();
          }
        }
        const uniqueViewsStrings = checkProduct[0]?.uniqueViews.map((id) =>
          id.toString()
        );
        if (checkProduct) {
          if (userId && !uniqueViewsStrings.includes(userId)) {
            checkProduct.uniqueViews.push(userId);
          }
          checkProduct.views += 1;
          await checkProduct.save();
        }
      }

      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: checkProduct,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getDetailsProductPublicBySlug = (slug, userId, params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const isViewed = params.isViewed ?? false;

      const checkProduct = await Product.aggregate([
        { $match: { slug: slug, status: 1 } },
        {
          $lookup: {
            from: "reviews",
            localField: "_id",
            foreignField: "product",
            as: "reviews",
          },
        },
        {
          $lookup: {
            from: "cities",
            localField: "location",
            foreignField: "_id",
            as: "locationInfo",
          },
        },
        {
          $lookup: {
            from: "producttypes",
            localField: "type",
            foreignField: "_id",
            as: "typeInfo",
          },
        },
        {
          $addFields: {
            averageRating: {
              $ifNull: [{ $avg: "$reviews.star" }, 0],
            },
            totalReviews: { $size: "$reviews" },
          },
        },
        {
          $project: {
            name: 1,
            image: 1,
            price: 1,
            countInStock: 1,
            description: 1,
            discount: 1,
            discountStartDate: 1,
            discountEndDate: 1,
            sold: 1,
            likedBy: 1,
            location: {
              $arrayElemAt: ["$locationInfo", 0],
            },
            type: {
              $arrayElemAt: ["$typeInfo", 0],
            },
            averageRating: 1,
            totalReviews: 1,
            // createdAt: 1,
            slug: 1,
            totalLikes: 1,
            views: 1,
            uniqueViews: 1,
          },
        },
      ]);

      if (checkProduct.length === 0) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The product is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }
      if (isViewed) {
        const user = await User.findById(userId);
        const productId = checkProduct[0]?._id?.toString();

        if (user) {
          const viewedProductsStrings = user?.viewedProducts?.map((id) =>
            id.toString()
          );
          if (productId && !viewedProductsStrings.includes(productId)) {
            user.viewedProducts.push(productId);

            await user.save();
          }
        }
        const uniqueViewsStrings = checkProduct[0]?.uniqueViews.map((id) =>
          id.toString()
        );

        if (checkProduct[0] && userId) {
          if (!uniqueViewsStrings?.includes(userId)) {
            checkProduct[0]?.uniqueViews?.push(userId);
          }
        }
        checkProduct[0].views += 1;
        await Product.findByIdAndUpdate(
          checkProduct[0]?._id?.toString(),
          checkProduct[0]
        );
      }

      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: checkProduct[0],
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getAllProduct = (params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = params?.limit ? +params?.limit : 10;
      const search = params?.search ?? "";
      const page = params?.page ? +params.page : 1;
      const order = params?.order ?? "createdAt desc";
      const productType = params?.productType ?? "";
      const productLocation = params?.productLocation ?? "";
      const minStar = +params?.minStar || 0;
      const maxStar = +params?.maxStar || 5;
      const minPrice = +params?.minPrice || 0;
      const maxPrice = +params?.maxPrice || Number.MAX_SAFE_INTEGER;
      const statusFilter = params?.status;
      const query = {};

      if (productType) {
        const productTypeIds = productType
          ?.split("|")
          .map((id) => mongoose.Types.ObjectId(id));
        query.type =
          productTypeIds.length > 1
            ? { $in: productTypeIds }
            : mongoose.Types.ObjectId(productType);
      }

      if (productLocation) {
        const productLocationIds = productLocation
          ?.split("|")
          .map((id) => mongoose.Types.ObjectId(id));
        query.type =
          productLocationIds.length > 1
            ? { $in: productLocationIds }
            : mongoose.Types.ObjectId(productLocation);
      }

      if (statusFilter !== undefined) {
        const statusFilterIds = statusFilter
          ?.split("|")
          .map((status) => +status);
        query.status =
          statusFilterIds.length > 1 ? { $in: statusFilterIds } : +statusFilter;
      }

      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [{ name: searchRegex }];
      }
      query.price = { $gte: minPrice, $lte: maxPrice };

      const totalCount = await Product.countDocuments(query);

      const totalPage = Math.ceil(totalCount / limit);

      const startIndex = (page - 1) * limit;

      let sortOptions = {};
      if (order) {
        const orderFields = order
          .split(",")
          .map((field) => field.trim().split(" "));
        orderFields.forEach(([name, direction]) => {
          sortOptions[name] = direction.toLowerCase() === "asc" ? 1 : -1;
        });
      }

      const fieldsToSelect = {
        image: 1,
        name: 1,
        createdAt: 1,
        price: 1,
        countInStock: 1,
        slug: 1,
        // totalLikes: 1,
        // averageRating: 1,
        type: 1,
        status: 1,
        type: {
          id: "$typeInfo._id",
          name: "$typeInfo.name",
        },
        // location: 1,
        // location: {
        //   id: "$locationInfo._id",
        //   name: "$locationInfo.name",
        // },
      };

      if (page === -1 && limit === -1) {
        const allProduct = await Product.aggregate([
          { $match: query },
          {
            $lookup: {
              from: "reviews",
              localField: "_id",
              foreignField: "product",
              as: "reviews",
            },
          },
          {
            $addFields: {
              averageRating: {
                $ifNull: [{ $avg: "$reviews.star" }, 0],
              },
            },
          },
          {
            $match: {
              "reviews.star": { $gte: minStar, $lte: maxStar },
            },
          },
          {
            $lookup: {
              from: "producttypes",
              localField: "type",
              foreignField: "_id",
              as: "typeInfo",
            },
          },
          {
            $unwind: "$typeInfo",
          },
          {
            $lookup: {
              from: "cities",
              localField: "location",
              foreignField: "_id",
              as: "locationInfo",
            },
          },
          {
            $unwind: {
              path: "$locationInfo",
              preserveNullAndEmptyArrays: true,
            },
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
            products: allProduct,
            totalPage: 1,
            totalCount: totalCount,
          },
        });
        return;
      }

      const pipeline = [
        { $match: query },
        { $sort: sortOptions },
        { $skip: startIndex },
        { $limit: limit },
        {
          $lookup: {
            from: "reviews",
            localField: "_id",
            foreignField: "product",
            as: "reviews",
          },
        },
        {
          $addFields: {
            averageRating: {
              $ifNull: [{ $avg: { $ifNull: ["$reviews.star", 0] } }, 0],
            },
          },
        },
        {
          $match: {
            $or: [
              { averageRating: { $gte: minStar, $lte: maxStar } },
              { averageRating: { $exists: false } },
            ],
          },
        },
        {
          $lookup: {
            from: "producttypes",
            localField: "type",
            foreignField: "_id",
            as: "typeInfo",
          },
        },
        {
          $unwind: "$typeInfo",
        },
        {
          $lookup: {
            from: "cities",
            localField: "location",
            foreignField: "_id",
            as: "locationInfo",
          },
        },
        {
          $unwind: { path: "$locationInfo", preserveNullAndEmptyArrays: true },
        },
        {
          $project: fieldsToSelect,
        },
      ];
      const allProduct = await Product.aggregate(pipeline);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        statusMessage: "Success",
        data: {
          products: allProduct,
          totalPage: totalPage,
          totalCount: totalCount,
        },
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getAllProductPublic = (params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = params?.limit ? +params?.limit : 10;
      const search = params?.search ?? "";
      const page = params?.page ? +params.page : 1;
      const order = params?.order ?? "createdAt desc";
      const productType = params?.productType ?? "";
      const productLocation = params?.productLocation ?? "";
      const minStar = +params?.minStar || 0;
      const maxStar = +params?.maxStar || 5;
      const minPrice = +params?.minPrice || 0;
      const maxPrice = +params?.maxPrice || Number.MAX_SAFE_INTEGER;
      const query = {};
      query.status = 1;

      if (productType) {
        const productTypeIds = productType
          ?.split("|")
          .map((id) => mongoose.Types.ObjectId(id));
        query.type =
          productTypeIds.length > 1
            ? { $in: productTypeIds }
            : mongoose.Types.ObjectId(productType);
      }

      if (productLocation) {
        const productLocationIds = productLocation
          ?.split("|")
          .map((id) => mongoose.Types.ObjectId(id));
        query.location =
          productLocationIds.length > 1
            ? { $in: productLocationIds }
            : mongoose.Types.ObjectId(productLocation);
      }

      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [{ name: searchRegex }];
      }
      query.price = { $gte: minPrice, $lte: maxPrice };

      const totalCount = await Product.countDocuments(query);

      const totalPage = Math.ceil(totalCount / limit);

      const startIndex = (page - 1) * limit;
      let sortOptions = {};
      if (order) {
        const orderFields = order
          .split(",")
          .map((field) => field.trim().split(" "));
        orderFields.forEach(([name, direction]) => {
          sortOptions[name] = direction.toLowerCase() === "asc" ? 1 : -1;
        });
      }

      const fieldsToSelect = {
        image: 1,
        name: 1,
        // createdAt: 1,
        price: 1,
        sold: 1,
        slug: 1,
        // totalLikes: 1,
        views: 1,
        uniqueViews: 1,
        averageRating: 1,
        totalReviews: 1,
        countInStock: 1,
        discount: 1,
        likedBy: 1,
        discountStartDate: 1,
        discountEndDate: 1,
        type: 1,
        type: {
          id: "$typeInfo._id",
          name: "$typeInfo.name",
        },
        location: 1,
        location: {
          id: "$locationInfo._id",
          name: "$locationInfo.name",
        },
      };

      if (page === -1 && limit === -1) {
        const allProduct = await Product.aggregate([
          { $match: query },
          {
            $lookup: {
              from: "reviews",
              localField: "_id",
              foreignField: "product",
              as: "reviews",
            },
          },
          {
            $addFields: {
              totalReviews: { $size: "$reviews" },
              averageRating: {
                $cond: {
                  if: { $gt: [{ $size: "$reviews" }, 0] },
                  then: { $avg: "$reviews.star" },
                  else: 0,
                },
              },
            },
          },
          {
            $match: {
              $or: [
                { totalReviews: { $eq: 0 } },
                { averageRating: { $gte: minStar, $lte: maxStar } },
              ],
            },
          },
          {
            $lookup: {
              from: "producttypes",
              localField: "type",
              foreignField: "_id",
              as: "typeInfo",
            },
          },
          {
            $unwind: "$typeInfo",
          },
          {
            $lookup: {
              from: "cities",
              localField: "location",
              foreignField: "_id",
              as: "locationInfo",
            },
          },
          {
            $unwind: {
              path: "$locationInfo",
              preserveNullAndEmptyArrays: true,
            },
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
            products: allProduct,
            totalPage: 1,
            totalCount: totalCount,
          },
        });
        return;
      }

      const pipeline = [
        { $match: query },
        { $sort: sortOptions },
        { $skip: startIndex },
        { $limit: limit },
        {
          $lookup: {
            from: "reviews",
            localField: "_id",
            foreignField: "product",
            as: "reviews",
          },
        },
        {
          $addFields: {
            totalReviews: { $size: "$reviews" },
            averageRating: {
              $cond: {
                if: { $gt: [{ $size: "$reviews" }, 0] },
                then: { $avg: "$reviews.star" },
                else: 0,
              },
            },
          },
        },
        {
          $match: {
            $or: [
              { totalReviews: { $eq: 0 } },
              { averageRating: { $gte: minStar, $lte: maxStar } },
            ],
          },
        },
        {
          $lookup: {
            from: "producttypes",
            localField: "type",
            foreignField: "_id",
            as: "typeInfo",
          },
        },
        {
          $unwind: "$typeInfo",
        },
        {
          $lookup: {
            from: "cities",
            localField: "location",
            foreignField: "_id",
            as: "locationInfo",
          },
        },
        {
          $unwind: { path: "$locationInfo", preserveNullAndEmptyArrays: true },
        },
        {
          $project: fieldsToSelect,
        },
      ];
      const allProduct = await Product.aggregate(pipeline);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        statusMessage: "Success",
        data: {
          products: allProduct,
          totalPage: totalPage,
          totalCount: totalCount,
        },
      });
    } catch (e) {
      reject(e);
    }
  });
};

const likeProduct = (productId, userId) => {
  return new Promise(async (resolve, reject) => {
    try {
      const existingUser = await User.findById(userId);
      const existingProduct = await Product.findById(productId);

      if (existingUser === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The user is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }
      if (existingProduct === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The product is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }
      if (existingUser.likedProducts?.includes(productId)) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The product is liked",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }
      existingUser.likedProducts.push(productId);
      existingProduct.totalLikes += 1;
      existingProduct.likedBy.push(existingUser._id);

      await existingUser.save();
      await existingProduct.save();
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Liked product success",
        typeError: "",
        data: null,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const unlikeProduct = (productId, userId) => {
  return new Promise(async (resolve, reject) => {
    try {
      const existingUser = await User.findById(userId);
      const existingProduct = await Product.findById(productId);

      if (existingUser === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The user is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }
      if (existingProduct === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The product is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }
      if (!existingUser.likedProducts?.includes(productId)) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The product isn't liked",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }
      existingUser.likedProducts = existingUser.likedProducts.filter((id) => {
        return id.toString() !== existingProduct._id.toString();
      });
      existingProduct.likedBy = existingProduct.likedBy.filter(
        (id) => id.toString() !== existingUser._id.toString()
      );
      if (existingProduct.totalLikes > 0) {
        existingProduct.totalLikes -= 1;
      }
      await existingProduct.save();
      await existingUser.save();
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "UnLiked product success",
        typeError: "",
        data: null,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const autoUpdateDiscounts = async () => {
  const currentDate = new Date();

  try {
    const productsToUpdate = await Product.find({
      discountEndDate: { $lte: currentDate },
      discount: { $gt: 0 },
    });

    for (const product of productsToUpdate) {
      product.discount = 0;
      await product.save();
    }
  } catch (error) {
    console.error("Error updating discounts:", error);
  }
};

const getAllProductViewed = (userId, params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = params?.limit ? +params?.limit : 10;
      const search = params?.search ?? "";
      const page = params?.page ? +params.page : 1;
      const query = {};

      const user = await User.findById(userId);
      if (!user || !user.viewedProducts) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
          message: "Success",
          typeError: "",
          data: {
            products: [],
            totalPage: 0,
            totalCount: 0,
          },
          statusMessage: "Success",
        });
        return;
      }

      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [{ name: searchRegex }];
      }
      const total = user?.viewedProducts?.length;

      const totalPage = Math.ceil(total / limit);

      const startIndex = (page - 1) * limit;
      const viewedProducts = await Product.find({
        _id: { $in: user.viewedProducts },
        ...query,
      })
        .skip(startIndex)
        .limit(limit);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: {
          products: viewedProducts,
          totalPage: totalPage,
          totalCount: total,
        },
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getAllProductLiked = (userId, params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = params?.limit ? +params?.limit : 10;
      const search = params?.search ?? "";
      const page = params?.page ? +params.page : 1;
      const user = await User.findById(userId);
      const query = {};

      if (!user || !user.likedProducts) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
          message: "Success",
          typeError: "",
          data: {
            products: [],
            totalPage: 0,
            totalCount: 0,
          },
          statusMessage: "Success",
        });
        return;
      }

      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [{ name: searchRegex }];
      }
      const total = user?.likedProducts?.length;

      const totalPage = Math.ceil(total / limit);

      const startIndex = (page - 1) * limit;
      const likedProducts = await Product.find({
        _id: { $in: user.likedProducts },
        ...query,
      })
        .skip(startIndex)
        .limit(limit);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: {
          products: likedProducts,
          totalPage: totalPage,
          totalCount: total,
        },
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getListRelatedProductBySlug = (params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = params?.limit ? +params?.limit : 10;
      const search = params?.search ?? "";
      const page = params?.page ? +params?.page : 1;
      const order = params?.order ?? "createdAt desc";
      const slug = params.slug;
      const query = {};
      query.status = 1;

      const checkProduct = await Product.findOne({ slug });

      if (checkProduct === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The product is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }
      query.slug = { $ne: slug };
      if (checkProduct.type) {
        query.type = mongoose.Types.ObjectId(checkProduct.type);
      }

      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [{ name: searchRegex }];
      }

      const totalCount = await Product.countDocuments(query);
      const totalPage = Math.ceil(totalCount / limit);

      const startIndex = (page - 1) * limit;

      let sortOptions = {};
      if (order) {
        const orderFields = order
          .split(",")
          .map((field) => field.trim().split(" "));
        orderFields.forEach(([name, direction]) => {
          sortOptions[name] = direction.toLowerCase() === "asc" ? 1 : -1;
        });
      }

      const fieldsToSelect = {
        image: 1,
        name: 1,
        createdAt: 1,
        price: 1,
        sold: 1,
        slug: 1,
        totalLikes: 1,
        averageRating: 1,
        totalReviews: 1,
        countInStock: 1,
        discount: 1,
        discountStartDate: 1,
        discountEndDate: 1,
        type: 1,
        type: {
          id: "$typeInfo._id",
          name: "$typeInfo.name",
        },
      };

      if (page === -1 && limit === -1) {
        const allProduct = await Product.aggregate([
          { $match: query },
          {
            $lookup: {
              from: "reviews",
              localField: "_id",
              foreignField: "product",
              as: "reviews",
            },
          },
          {
            $addFields: {
              averageRating: {
                $ifNull: [{ $avg: { $ifNull: ["$reviews.star", 0] } }, 0],
                totalReviews: { $size: "$reviews" },
              },
            },
          },
          {
            $lookup: {
              from: "producttypes",
              localField: "type",
              foreignField: "_id",
              as: "typeInfo",
            },
          },
          {
            $unwind: "$typeInfo",
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
            products: allProduct,
            totalPage: totalPage,
            totalCount: totalCount,
          },
        });
        return;
      }
    
      const pipeline = [
        { $match: query },
        { $sort: sortOptions },
        { $skip: startIndex },
        { $limit: limit },
        {
          $lookup: {
            from: "reviews",
            localField: "_id",
            foreignField: "product",
            as: "reviews",
          },
        },
        {
          $addFields: {
            averageRating: {
              $ifNull: [{ $avg: { $ifNull: ["$reviews.star", 0] } }, 0],
            },
            totalReviews: { $size: "$reviews" },
          },
        },
        {
          $lookup: {
            from: "producttypes",
            localField: "type",
            foreignField: "_id",
            as: "typeInfo",
          },
        },
        {
          $unwind: "$typeInfo",
        },
        {
          $project: fieldsToSelect,
        },
      ];

      const allProduct = await Product.aggregate(pipeline);
      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        statusMessage: "Success",
        data: {
          products: allProduct,
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
  createProduct,
  updateProduct,
  getDetailsProduct,
  deleteProduct,
  getAllProduct,
  deleteManyProduct,
  likeProduct,
  unlikeProduct,
  getDetailsProductPublic,
  getAllProductPublic,
  getAllProductViewed,
  getAllProductLiked,
  getDetailsProductPublicBySlug,
  getListRelatedProductBySlug,
};
