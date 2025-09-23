const Order = require("../models/Order");
const { publishToQueue } = require("../utils/rabbitmq");
const { notifyRestaurantService } = require("../rest-client/restaurentApi");
const mongoose = require("mongoose");

const handleOrderCreation = async ({
  userId,
  restaurantId,
  items,
  totalAmount,
  status,
}) => {
  const newOrder = new Order({
    userId,
    restaurantId,
    items,
    totalAmount,
    status,
  });

  const savedOrder = await newOrder.save();

  // Publish to RabbitMQ
  publishToQueue("order_created", savedOrder);

  // Notify Restaurant Service
  await notifyRestaurantService(savedOrder);

  return savedOrder;
};

// ===================Prevent IDOR by ensuring only the owner can update their order==============
const handleOrderStatusUpdate = async (orderId, status, userId) => {

   if (!mongoose.Types.ObjectId.isValid(orderId)) return null;

   const order = await Order.findById(orderId);

  if (!order) return null;

  // Only owner can update
  if (order.userId.toString() !== userId) return null;

  order.status = status;
  return await order.save();
};

const getUserOrdersFromDB = async (userId) => {
  return await Order.find({ userId })
    .populate("items.itemId")
    .populate("restaurantId", "name address");
};

const cancelUserOrder = async (orderId, userId) => {

  // Validate orderId       ===prevent IDOR=====
  if (!mongoose.Types.ObjectId.isValid(orderId)) return null;

  // Find the order first
  const order = await Order.findById(orderId);
  
  if (!order) {
    return null;
  }

  // Verify the user owns the order
  if (order.userId.toString() !== userId) {
    return null;
  }

  // Check if order is in a cancellable state
  // const cancellableStatuses = ["preparing", "searching-drivers"];
  // if (!cancellableStatuses.includes(order.status)) {
  //   return null;
  // }

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
