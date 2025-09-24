const mongoose = require("mongoose");
const Driver = require("../models/driver");

// Allowed statuses (adjust to match your schema enum)
const ALLOWED_STATUSES = ["available", "assigned", "offline"];

// -- helpers ---------------------------------------------------------------

function assertObjectId(id, fieldName = "id") {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    throw new Error(`Invalid ${fieldName}`);
  }
  return id;
}

function assertStatus(value) {
  if (!ALLOWED_STATUSES.includes(value)) {
    throw new Error(`Invalid status`);
  }
  return value;
}

// Accept either [lng, lat] as numbers, or GeoJSON { type:"Point", coordinates:[lng,lat] }
function normalizeLocation(input) {
  // GeoJSON Point object
  if (
    input &&
    typeof input === "object" &&
    input.type === "Point" &&
    Array.isArray(input.coordinates) &&
    input.coordinates.length === 2 &&
    Number.isFinite(input.coordinates[0]) &&
    Number.isFinite(input.coordinates[1])
  ) {
    return { type: "Point", coordinates: [input.coordinates[0], input.coordinates[1]] };
  }

  // [lng, lat] array
  if (
    Array.isArray(input) &&
    input.length === 2 &&
    Number.isFinite(input[0]) &&
    Number.isFinite(input[1])
  ) {
    return { type: "Point", coordinates: [input[0], input[1]] };
  }

  throw new Error("Invalid coordinates format");
}

// Common options: run schema validators, return updated doc
const UPDATE_OPTS = { new: true, runValidators: true, context: "query" };

// -- queries ---------------------------------------------------------------

const getAvailable = async () => {
  return await Driver.find({ status: "available" });
};

// Simulated — in reality, you'd use $near queries with location
const findAvailableNearby = async () => {
  return await Driver.findOne({ status: "available" });
};

const markAssigned = async (driverId) => {
  assertObjectId(driverId, "driverId");
  // enforce known status value
  const status = assertStatus("assigned");
  return await Driver.findByIdAndUpdate(
    driverId,
    { status },
    UPDATE_OPTS
  );
};

const updateLocation = async (driverId, coordinates) => {
  assertObjectId(driverId, "driverId");
  const safePoint = normalizeLocation(coordinates);

  return await Driver.findByIdAndUpdate(
    driverId,
    { currentLocation: safePoint },
    UPDATE_OPTS
  );
};

const getLocation = async (driverId) => {
  assertObjectId(driverId, "driverId");
  return await Driver.findById(driverId, "currentLocation");
};

module.exports = {
  getAvailable,
  findAvailableNearby,
  markAssigned,
  updateLocation,
  getLocation,
};
