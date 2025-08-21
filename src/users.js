const users = new Map();

console.log("users.js loaded");
export function getOrCreateUser(user) {
  if (!users.has(user.id)) {
    users.set(user.id, user);
  }
  console.log("User retrieved or created:", users);
  return users.get(user.id);
}

export function getUserById(id) {
  return users.get(id);
}

export function getAllUsers() {
  return Array.from(users.values());
}