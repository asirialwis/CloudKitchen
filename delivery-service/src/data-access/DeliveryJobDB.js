const mongoose = require("mongoose");
const Delivery = require("../models/deliveryJob");

const ALLOWED_STATUSES = ["pending", "assigned", "in-progress", "delivered", "cancelled"];

function validateObjectId(id, fieldName) {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    throw new Error(`Invalid ${fieldName}`);
  }
  return id;
}

function validateStatus(status) {
  if (!ALLOWED_STATUSES.includes(status)) {
    throw new Error(`Invalid status value`);
  }
  return status;
}

const createDelivery = async (data) => {
  // Whitelist only safe fields
  const safeData = {
    restaurantId: data.restaurantId && validateObjectId(data.restaurantId, "restaurantId"),
    orderId: data.orderId && validateObjectId(data.orderId, "orderId"),
    driverId: data.driverId && validateObjectId(data.driverId, "driverId"),
    customerId: data.customerId && validateObjectId(data.customerId, "customerId"),
    status: data.status ? validateStatus(data.status) : "pending",
  };

  const delivery = new Delivery(safeData);
  return await delivery.save();
};

const assignDriver = async (deliveryId, driverId) => {
  validateObjectId(deliveryId, "deliveryId");
  validateObjectId(driverId, "driverId");

  return await Delivery.findByIdAndUpdate(
    deliveryId,
    { driverId, status: "assigned" },
    { new: true }
  );
};

const updateStatus = async (id, status) => {
  validateObjectId(id, "deliveryId");
  const safeStatus = validateStatus(status);

  return await Delivery.findByIdAndUpdate(id, { status: safeStatus }, { new: true });
};

const updateDeliveryJob = async (deliveryJob) => {
  validateObjectId(deliveryJob._id, "deliveryJob._id");

  const updateData = {};
  if (deliveryJob.driverId && mongoose.Types.ObjectId.isValid(deliveryJob.driverId)) {
    updateData.driverId = deliveryJob.driverId;
  }
  if (deliveryJob.status) {
    updateData.status = validateStatus(deliveryJob.status);
  }

  return await Delivery.findByIdAndUpdate(deliveryJob._id, updateData, { new: true });
};

const getById = async (id) => {
  validateObjectId(id, "deliveryId");
  return await Delivery.findById(id).populate("restaurantId");
};

const getByOrderId = async (orderId) => {
  validateObjectId(orderId, "orderId");
  return await Delivery.findOne({ orderId }).populate(["driverId", "customerId"]);
};

const getPendingDeliveries = async () => {
  return await Delivery.find({ status: "pending" });
};

module.exports = {
  createDelivery,
  assignDriver,
  updateStatus,
  getById,
  getPendingDeliveries,
  updateDeliveryJob,
  getByOrderId,
};
