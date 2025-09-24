const Restaurant = require("../models/restaurant");
const MenuItem = require("../models/menuItem");
const RestaurantJob = require("../models/restaurantJob");
const mongoose = require("mongoose");

const getAllRestaurants = async () => {
  return await Restaurant.find().populate("menuItems");
};

const getAllReadyRestaurantJobs = async () => {
  return await RestaurantJob.find({ status: "ready" }).populate([
    "items.itemId",
    "userId",
    "restaurantId",
  ]);
};

const createRestaurant = async (data) => {
  //NoSQL injection prevention
  const allowed = (({
    name,
    ownerId,
    description,
    address,
    contactNumber,
    imageUrl,
    location,
  }) => ({
    name,
    ownerId,
    description,
    address,
    contactNumber,
    imageUrl,
    location,
    isAvailable,
  }))(data);
  const restaurant = new Restaurant(allowed);
  return await restaurant.save();
};

const createRestaurantJob = async (data) => {
  const restaurantJob = new RestaurantJob(data);
  return await restaurantJob.save();
};

const updateRestaurant = async (id, data) => {
  //NoSQL injection prevention
  const allowed = (({ name, address, isAvailable }) => ({
    name,
    address,
    isAvailable,
  }))(data);
  return await Restaurant.findByIdAndUpdate(id, allowed, { new: true });
};

const setAvailability = async (id, isAvailable) => {
  //NoSQL injection prevention
  const available = Boolean(isAvailable);
  return await Restaurant.findByIdAndUpdate(
    id,
    { isAvailable: available },
    { new: true }
  );
};

const getMenuItems = async (restaurantId) => {
  //NoSQL injection prevention
  if (!mongoose.Types.ObjectId.isValid(restaurantId))
    throw new Error("Invalid ID");

  return await MenuItem.find({ restaurantId });
};

const addMenuItem = async (restaurantId, menuItemData) => {
  //NoSQL injection prevention
  if (!mongoose.Types.ObjectId.isValid(restaurantId))
    throw new Error("Invalid ID");

  const allowed = (({
    restaurantId,
    name,
    description,
    price,
    imageUrl,
    category,
  }) => ({
    restaurantId,
    name,
    description,
    price,
    imageUrl,
    category,
  }))(menuItemData);

  const menuItem = new MenuItem({ ...allowed, restaurantId });
  const saved = await menuItem.save();
  
  await Restaurant.findByIdAndUpdate(restaurantId, {
    $push: { menuItems: saved._id },
  });
  return saved;
};

const updateMenuItem = async (id, data) => {
  //NoSQL injection prevention
  const allowed = (({ name, price, description }) => ({
    name,
    price,
    description,
  }))(data);
  return await MenuItem.findByIdAndUpdate(id, allowed, { new: true });
};

const deleteMenuItem = async (id) => {
  //NoSQL injection prevention
  if (!mongoose.Types.ObjectId.isValid(id)) throw new Error("Invalid ID");

  const menuItem = await MenuItem.findById(id);
  if (menuItem) {
    await Restaurant.findByIdAndUpdate(menuItem.restaurantId, {
      $pull: { menuItems: id },
    });
    await MenuItem.findByIdAndDelete(menuItem._id);
  }
};

const setRestaurantJobStatus = async (jobId, status) => {
  //NoSQL injection prevention
  if (!mongoose.Types.ObjectId.isValid(jobId))
    throw new Error("Invalid ID");

  const allowedStatuses = ["preparing", "ready", "done"];
  if (!allowedStatuses.includes(status)) throw new Error("Invalid status");
  
  return await RestaurantJob.findByIdAndUpdate(
    jobId,
    { status: status },
    { new: true }
  );
};

module.exports = {
  getAllRestaurants,
  getAllReadyRestaurantJobs,
  createRestaurant,
  createRestaurantJob,
  updateRestaurant,
  setAvailability,
  getMenuItems,
  addMenuItem,
  updateMenuItem,
  deleteMenuItem,
  setRestaurantJobStatus,
};
