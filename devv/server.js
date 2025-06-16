require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const currency = require('currency.js');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✨ MongoDB connected'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Database Models
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: '' },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const ExpenseSchema = new mongoose.Schema({
  amount: { type: Number, required: true, min: 0 },
  description: { type: String, required: true },
  paidBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  splitType: { 
    type: String, 
    enum: ['EQUAL', 'PERCENTAGE', 'EXACT'], 
    default: 'EQUAL' 
  },
  shares: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: 0 }
  }],
  category: { 
    type: String, 
    enum: ['Food', 'Travel', 'Utilities', 'Entertainment', 'Other'], 
    default: 'Other' 
  },
  createdAt: { type: Date, default: Date.now }
});

const FriendRequestSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { 
    type: String, 
    enum: ['PENDING', 'ACCEPTED', 'REJECTED'], 
    default: 'PENDING' 
  },
  createdAt: { type: Date, default: Date.now }
});

const GroupSchema = new mongoose.Schema({
  name: { type: String, required: true },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const SettlementSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true, min: 0 },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Expense = mongoose.model('Expense', ExpenseSchema);
const FriendRequest = mongoose.model('FriendRequest', FriendRequestSchema);
const Group = mongoose.model('Group', GroupSchema);
const Settlement = mongoose.model('Settlement', SettlementSchema);

// Utility Functions
const calculateBalances = async () => {
  const expenses = await Expense.find().populate('paidBy shares.user');
  
  const balances = {};
  expenses.forEach(expense => {
    const paidBy = expense.paidBy._id.toString();
    
    if (!balances[paidBy]) {
      balances[paidBy] = currency(0);
    }
    balances[paidBy] = balances[paidBy].add(expense.amount);
    
    expense.shares.forEach(share => {
      const userId = share.user._id.toString();
      
      if (!balances[userId]) {
        balances[userId] = currency(0);
      }
      balances[userId] = balances[userId].subtract(share.amount);
    });
  });
  
  return balances;
};

const optimizeSettlements = (balances) => {
  const creditors = [];
  const debtors = [];
  const transactions = [];
  
  // Separate into creditors and debtors
  Object.entries(balances).forEach(([userId, balance]) => {
    const amount = currency(balance).value;
    if (amount > 0) {
      creditors.push({ userId, amount });
    } else if (amount < 0) {
      debtors.push({ userId, amount: Math.abs(amount) });
    }
  });
  
  // Sort by amount
  creditors.sort((a, b) => b.amount - a.amount);
  debtors.sort((a, b) => b.amount - a.amount);
  
  // Calculate optimized transactions
  while (creditors.length > 0 && debtors.length > 0) {
    const creditor = creditors[0];
    const debtor = debtors[0];
    
    const settleAmount = Math.min(creditor.amount, debtor.amount);
    
    transactions.push({
      from: debtor.userId,
      to: creditor.userId,
      amount: settleAmount
    });
    
    creditor.amount = currency(creditor.amount).subtract(settleAmount).value;
    debtor.amount = currency(debtor.amount).subtract(settleAmount).value;
    
    if (creditor.amount === 0) creditors.shift();
    if (debtor.amount === 0) debtors.shift();
  }
  
  return transactions;
};

// Generate avatar color based on user ID
const generateAvatarColor = (userId) => {
  const colors = [
    '#FF6B6B', '#4ECDC4', '#45B7D1', '#FFBE0B', '#FB5607', 
    '#8338EC', '#3A86FF', '#FF006E', '#8AC926', '#1982C4'
  ];
  const hash = crypto.createHash('md5').update(userId).digest('hex');
  const index = parseInt(hash.substring(0, 8), 16) % colors.length;
  return colors[index];
};

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: '🔒 Unauthorized' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.userId).select('-password');
    next();
  } catch (err) {
    res.status(401).json({ error: '❌ Invalid token' });
  }
};

// Socket.io connections
const userSockets = {};

io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  
  socket.on('register', (userId) => {
    userSockets[userId] = socket.id;
    console.log(`User ${userId} registered with socket ${socket.id}`);
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
    // Remove from userSockets mapping
    Object.keys(userSockets).forEach(userId => {
      if (userSockets[userId] === socket.id) {
        delete userSockets[userId];
      }
    });
  });
});

// Function to send socket events to specific users
const sendToUser = (userId, event, data) => {
  const socketId = userSockets[userId];
  if (socketId) {
    io.to(socketId).emit(event, data);
  }
};

// Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: '❌ All fields are required' });
    }
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: '📧 Email already registered' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });
    
    await user.save();
    
    // Generate avatar color
    const avatarColor = generateAvatarColor(user._id.toString());
    user.avatar = `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=${avatarColor.replace('#', '')}&color=fff&rounded=true`;
    await user.save();
    
    // Generate JWT
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '30d'
    });
    
    res.status(201).json({
      _id: user._id,
      username: user.username,
      email: user.email,
      avatar: user.avatar,
      token
    });
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: '❌ Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: '❌ Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '30d'
    });
    
    res.json({
      _id: user._id,
      username: user.username,
      email: user.email,
      avatar: user.avatar,
      token
    });
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

// User Endpoints
app.get('/api/users/:id', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).populate('friends', 'username avatar');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const { email } = req.query;
    let query = {};
    
    if (email) {
      query.email = email;
    }
    
    const users = await User.find(query).select('-password');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

// Expense Endpoints
app.post('/api/expenses', authMiddleware, async (req, res) => {
  try {
    const { amount, description, paidBy, splitType, shares, category } = req.body;
    
    // Validation
    if (!amount || !description || !paidBy || !splitType || !shares || shares.length === 0) {
      return res.status(400).json({ error: '❌ Missing required fields' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ error: '💰 Amount must be positive' });
    }
    
    // Create expense
    const expense = new Expense({
      amount,
      description,
      paidBy,
      splitType,
      shares,
      category
    });
    
    await expense.save();
    
    // Populate for response
    const populatedExpense = await Expense.findById(expense._id)
      .populate('paidBy', 'username avatar')
      .populate('shares.user', 'username avatar');
      
    // Notify other users
    shares.forEach(share => {
      if (share.user.toString() !== paidBy && share.user.toString() !== req.user._id.toString()) {
        sendToUser(share.user.toString(), 'expenseAdded', populatedExpense);
      }
    });
    
    res.status(201).json(populatedExpense);
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

app.get('/api/expenses', authMiddleware, async (req, res) => {
  try {
    const expenses = await Expense.find()
      .populate('paidBy', 'username avatar')
      .populate('shares.user', 'username avatar')
      .sort({ createdAt: -1 });
      
    res.json(expenses);
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

app.put('/api/expenses/:id', authMiddleware, async (req, res) => {
  try {
    const { amount, description, paidBy, splitType, shares, category } = req.body;
    const expenseId = req.params.id;
    
    // Validation
    if (!amount || !description || !paidBy || !splitType || !shares || shares.length === 0) {
      return res.status(400).json({ error: '❌ Missing required fields' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ error: '💰 Amount must be positive' });
    }
    
    // Find and update expense
    const expense = await Expense.findByIdAndUpdate(
      expenseId,
      {
        amount,
        description,
        paidBy,
        splitType,
        shares,
        category
      },
      { new: true }
    )
    .populate('paidBy', 'username avatar')
    .populate('shares.user', 'username avatar');
    
    if (!expense) {
      return res.status(404).json({ error: 'Expense not found' });
    }
    
    res.json(expense);
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

app.delete('/api/expenses/:id', authMiddleware, async (req, res) => {
  try {
    const expense = await Expense.findById(req.params.id);
    if (!expense) {
      return res.status(404).json({ error: 'Expense not found' });
    }
    
    // Only allow payer to delete
    if (expense.paidBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Only the payer can delete this expense' });
    }
    
    await Expense.findByIdAndDelete(req.params.id);
    res.json({ message: 'Expense deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

// Settlement Endpoints
app.post('/api/settlements', authMiddleware, async (req, res) => {
  try {
    const { payer } = req.body;
    if (!payer) {
      return res.status(400).json({ error: 'Payer ID is required' });
    }
    
    const balances = await calculateBalances();
    const settlements = optimizeSettlements(balances);
    
    // Find settlement for the payer
    const payerSettlement = settlements.find(s => 
      s.from === payer || s.to === payer
    );
    
    if (!payerSettlement) {
      return res.status(400).json({ error: 'No settlement needed for this payer' });
    }
    
    // Create settlement record
    const settlement = new Settlement({
      from: payerSettlement.from,
      to: payerSettlement.to,
      amount: payerSettlement.amount
    });
    
    await settlement.save();
    
    // Populate for response
    const populatedSettlement = await Settlement.findById(settlement._id)
      .populate('from', 'username avatar')
      .populate('to', 'username avatar');
    
    // Notify both parties
    sendToUser(payerSettlement.from, 'settlement', populatedSettlement);
    sendToUser(payerSettlement.to, 'settlement', populatedSettlement);
    
    res.status(201).json(populatedSettlement);
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

app.get('/api/settlements', authMiddleware, async (req, res) => {
  try {
    const balances = await calculateBalances();
    const settlements = optimizeSettlements(balances);
    
    // Populate user details
    const populatedSettlements = await Promise.all(
      settlements.map(async t => {
        const fromUser = await User.findById(t.from);
        const toUser = await User.findById(t.to);
        return {
          from: fromUser.username,
          fromId: fromUser._id,
          to: toUser.username,
          toId: toUser._id,
          amount: t.amount
        }
      })
    );
    
    res.json(populatedSettlements);
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

// Friend Endpoints
app.post('/api/friends/request', authMiddleware, async (req, res) => {
  try {
    const { toUserId } = req.body;
    
    if (req.user._id.toString() === toUserId) {
      return res.status(400).json({ error: '🤔 Cannot send request to yourself' });
    }
    
    // Check if request already exists
    const existingRequest = await FriendRequest.findOne({
      from: req.user._id,
      to: toUserId
    });
    
    if (existingRequest) {
      return res.status(400).json({ error: '📩 Friend request already sent' });
    }
    
    // Create request
    const request = new FriendRequest({
      from: req.user._id,
      to: toUserId,
      status: 'PENDING'
    });
    
    await request.save();
    
    // Populate for response
    const populatedRequest = await FriendRequest.findById(request._id)
      .populate('from', 'username avatar')
      .populate('to', 'username avatar');
    
    // Notify recipient
    sendToUser(toUserId, 'friendRequest', populatedRequest);
      
    res.status(201).json(populatedRequest);
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

app.put('/api/friends/request/:id', authMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    const requestId = req.params.id;
    
    const request = await FriendRequest.findById(requestId)
      .populate('from', 'username avatar')
      .populate('to', 'username avatar');
    
    if (!request) {
      return res.status(404).json({ error: '🔍 Request not found' });
    }
    
    if (request.to._id.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: '🚫 Unauthorized' });
    }
    
    request.status = status;
    await request.save();
    
    if (status === 'ACCEPTED') {
      // Add to friends list
      await User.findByIdAndUpdate(req.user._id, {
        $addToSet: { friends: request.from }
      });
      
      await User.findByIdAndUpdate(request.from, {
        $addToSet: { friends: req.user._id }
      });
    }
    
    res.json(request);
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

app.get('/api/friend-requests', authMiddleware, async (req, res) => {
  try {
    const requests = await FriendRequest.find({ 
      to: req.user._id,
      status: 'PENDING'
    }).populate('from', 'username avatar');
    
    res.json(requests);
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

// Group Endpoints
app.post('/api/groups', authMiddleware, async (req, res) => {
  try {
    const { name, members } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: '❌ Group name is required' });
    }
    
    // Include current user in members
    const allMembers = [...new Set([...members, req.user._id.toString()])];
    
    const group = new Group({
      name,
      members: allMembers,
      createdBy: req.user._id
    });
    
    await group.save();
    
    // Populate members for response
    const populatedGroup = await Group.findById(group._id).populate('members', 'username avatar');
    
    res.status(201).json(populatedGroup);
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

app.get('/api/groups', authMiddleware, async (req, res) => {
  try {
    const groups = await Group.find({
      members: req.user._id
    }).populate('members', 'username avatar');
    
    res.json(groups);
  } catch (err) {
    res.status(500).json({ error: '🔥 Server error: ' + err.message });
  }
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});