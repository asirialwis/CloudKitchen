const mongoose = require("mongoose");
const Order = require("../models/Order");
const { publishToQueue } = require("../utils/rabbitmq");
const { notifyRestaurantService } = require("../rest-client/restaurentApi");

// Allowed order statuses to prevent injection or invalid state updates
const ALLOWED_STATUSES = [
  "pending",
  "preparing",
  "searching-drivers",
  "on-the-way",
  "delivered",
  "cancelled",
];

/**
 * Validate ObjectId inputs to prevent NoSQL injection.
 */
function validateObjectId(id, fieldName) {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    throw new Error(`Invalid ${fieldName}`);
  }
  return id;
}

/**
 * Validate order status to prevent operator injection or invalid states.
 */
function validateStatus(status) {
  if (!ALLOWED_STATUSES.includes(status)) {
    throw new Error("Invalid order status");
  }
  return status;
}

const handleOrderCreation = async ({
  userId,
  restaurantId,
  items,
  totalAmount,
  status,
}) => {
  // Validate IDs
  validateObjectId(userId, "userId");
  validateObjectId(restaurantId, "restaurantId");

  // Validate status
  const safeStatus = validateStatus(status);

  const newOrder = new Order({
    userId,
    restaurantId,
    items,
    totalAmount,
    status: safeStatus,
  });

  const savedOrder = await newOrder.save();

  // Publish to RabbitMQ
  publishToQueue("order_created", savedOrder);

  // Notify Restaurant Service
  await notifyRestaurantService(savedOrder);

  return savedOrder;
};

const handleOrderStatusUpdate = async (orderId, status) => {
  // Validate inputs
  validateObjectId(orderId, "orderId");
  const safeStatus = validateStatus(status);

  const updatedOrder = await Order.findByIdAndUpdate(
    orderId,
    { status: safeStatus },
    { new: true }
  );

  return updatedOrder;
};

const getUserOrdersFromDB = async (userId) => {
  validateObjectId(userId, "userId");

  return await Order.find({ userId })
    .populate("items.itemId")
    .populate("restaurantId", "name address");
};

const cancelUserOrder = async (orderId, userId) => {
  validateObjectId(orderId, "orderId");
  validateObjectId(userId, "userId");

  // Find the order first
  const order = await Order.findById(orderId);
  if (!order) {
    return null;
  }

  // Verify the user owns the order
  if (order.userId.toString() !== userId) {
    return null;
  }

  // Update the status to cancelled
  order.status = "cancelled";
  const updatedOrder = await order.save();

  return updatedOrder;
};

module.exports = {
  handleOrderCreation,
  handleOrderStatusUpdate,
  getUserOrdersFromDB,
  cancelUserOrder,
};
