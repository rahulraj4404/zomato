const express = require('express');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
const path = require('path');
const bcrypt = require('bcrypt');
const cookieparser = require('cookie-parser');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/zomato')
  .then(() => console.log("connected to mongodb"))
  .catch(err => console.error('could not connect to mongodb'));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(cookieparser());

const secretkey = process.env.JWT_SECRET;

const userschema = new mongoose.Schema({
  username: { type: String, required: true },
  phoneno: { type: Number, required: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
});

const user = mongoose.model('user', userschema);

const menuschema = new mongoose.Schema({
  itemname: { type: String, required: true },
  price: { type: Number, required: true },
});

const feedbackschema = new mongoose.Schema({
  username: { type: String, required: true },
  message: { type: String, required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
});

const restaurantownerschema = new mongoose.Schema({
  restaurantname: { type: String, required: true },
  phoneno: { type: Number, required: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  menu: [menuschema],
  feedbacks: [feedbackschema],
});

const restaurantowner = mongoose.model('restaurantowner', restaurantownerschema);

const orderitemschema = new mongoose.Schema({
  itemname: { type: String, required: true },
  price: { type: Number, required: true },
  quantity: { type: Number, required: true },
  rating: { type: Number },
});

const orderschema = new mongoose.Schema({
  orderid: { type: String, unique: true, required: true },
  restaurantname: { type: String, required: true },
  username: { type: String, required: true },
  items: [orderitemschema],
  totalprice: { type: String, required: true },
  status: {
    type: String,
    enum: ['Pending', 'Confirmed', 'Cancelled', 'Delivered'],
    default: 'Pending',
  },
  createdat: { type: Date, default: Date.now },
  updatedat: { type: Date, default: Date.now },
});
const orders = mongoose.model('orders', orderschema);
function authorizerequest(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    return res.status(403).send('Access Denied');
  }
  try {
    const verified = jwt.verify(token, secretkey);
    req.userid = verified.userid;
    next();
  } catch (error) {
    return res.status(400).send('Invalid Token');
  }
}

app.get('/', (req, res) => {
  res.render('mainpage');
});

app.post('/owner/register', async (req, res) => {
  try {
    const { restaurantname, phoneno, email, password } = req.body;
    const hashedpassword = await bcrypt.hash(password, 10);
    const newrestaurantowner = new restaurantowner({ restaurantname, phoneno, email, password: hashedpassword });
    await newrestaurantowner.save();
    res.redirect('/');
  } catch (error) {
    res.status(500).send("Error in registering, please try again");
    console.log('Error in registering restaurant owner', error);
  }
});

app.post('/owner/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const findrestaurantowner = await restaurantowner.findOne({ email });
    if (!findrestaurantowner) {
      return res.status(401).send("Invalid restaurant owner details");
    }
    const hashedpassword = await bcrypt.compare(password, findrestaurantowner.password);
    if (!hashedpassword) {
      return res.status(401).send('Password incorrect');
    }
    const token = jwt.sign({ userid: findrestaurantowner._id }, secretkey, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/owner');
  } catch (error) {
    res.status(401).send("Invalid status");
    console.log('Cannot login ', error);
  }
});

app.post('/user/register', async (req, res) => {
  try {
    const { username, phoneno, email, password } = req.body;
    const existinguser = await user.findOne({ username });
    if (existinguser) {
      return res.status(400).send('Username already exists');
    }
    const hashedpassword = await bcrypt.hash(password, 10);
    const newuser = new user({ username, phoneno, email, password: hashedpassword });
    await newuser.save();
    res.redirect('/restaurants');
  } catch (error) {
    res.status(500).send('Server error');
    console.log('Error registering user ', error);
  }
});

app.post('/user/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const finduser = await user.findOne({ email });
    if (!finduser) {
      return res.status(401).send('Invalid username');
    }
    const match = await bcrypt.compare(password, finduser.password);
    if (!match) {
      return res.status(401).send('Invalid password');
    }
    const token = jwt.sign({ userid: finduser._id }, secretkey, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/restaurants',);
  } catch (error) {
    console.error('Error logging in user', error);
    res.status(500).send('Internal server error');
  }
});

app.get('/owner', authorizerequest, async (req, res) => {
  try {
    const restaurant = await restaurantowner.findById(req.userid);
    if (!restaurant) {
      return res.status(404).send('Restaurant owner not found');
    }
    const ordersList = await orders.find({ restaurantname: restaurant.restaurantname });

    res.render('layout', { ownerid: restaurant._id, restaurant,orders:ordersList });
  } catch (error) {
    res.status(500).send('Server error');
    console.log('Error fetching restaurant owner', error);
  }
});
app.post('/:ownerid/addmenu', authorizerequest, async (req, res) => {
  try {
    const ownerid = req.params.ownerid.trim();
    const { itemname, price } = req.body;
    if (!itemname || !price) {
      return res.status(400).json({ message: 'Item name and price are required' });
    }
    const findrestaurant = await restaurantowner.findById(ownerid);
    if (!findrestaurant) {
      return res.status(404).json({ message: 'Restaurant not found' });
    }
    const newmenuitem = { itemname, price };
    findrestaurant.menu.push(newmenuitem);
    await findrestaurant.save();
    res.render('layout', { restaurant: findrestaurant, ownerid: ownerid });
  } catch (error) {
    console.error('Error adding menu item', error);
    res.status(500).json({ message: 'An error occurred while adding' });
  }
});
app.post('/owner/:ownerid/edit/:detailType', authorizerequest, async (req, res) => {
    try {
      const { ownerid, detailType } = req.params;
      const { value } = req.body;
      const allowedDetails = ['restaurantname', 'phoneno', 'email'];
  
      if (!allowedDetails.includes(detailType)) {
        return res.status(400).json({ error: 'Invalid detail type' });
      }
  
      const updatedFields = { [detailType]: value };
      const updatedRestaurant = await restaurantowner.findByIdAndUpdate(ownerid, updatedFields, { new: true });
  
      if (!updatedRestaurant) {
        return res.status(404).json({ error: 'Restaurant owner not found' });
      }
      res.render('layout',{restaurant:updatedRestaurant,ownerid:ownerid});
    //   res.json({ message: 'Detail updated successfully', restaurant: updatedRestaurant });
    } catch (error) {
      console.error('Error updating restaurant detail', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/owner/:ownerid/editmenu/:itemid', authorizerequest, async (req, res) => {
    try {
      const { ownerid, itemid } = req.params;
      const { itemname, price } = req.body;
      if (!itemname || price === undefined) {
        return res.status(400).json({ error: 'Item name and price are required' });
      }
  
      const restaurant = await restaurantowner.findById(ownerid);
      if (!restaurant) {
        return res.status(404).json({ error: 'Restaurant owner not found' });
      }
  
      const menuItem = restaurant.menu.id(itemid);
      if (!menuItem) {
        return res.status(404).json({ error: 'Menu item not found' });
      }
      menuItem.itemname = itemname;
      menuItem.price = price;
      await restaurant.save();
    //   res.json({ message: 'Menu item updated successfully', menuItem });
      res.render('layout',{ownerid:ownerid,restaurant:restaurant});
    } catch (error) {
      console.error('Error updating menu item', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/owner/:ownerid/deletemenu/:itemid', authorizerequest, async (req, res) => {
    try {
      const { ownerid, itemid } = req.params;
  
      const restaurant = await restaurantowner.findById(ownerid);
      if (!restaurant) {
        return res.status(404).json({ error: 'Restaurant owner not found' });
      }
      restaurant.menu.pull({ _id: itemid });
      await restaurant.save();
    //   res.json({ message: 'Menu item deleted successfully' });
    res.render('layout',{ownerid:ownerid,restaurant:restaurant})
    } catch (error) {
      console.error('Error deleting menu item', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

app.get('/restaurants', async (req, res) => {
    console.log('Fetching restaurants...'); 
    try {
            const restaurants = await restaurantowner.find();
            res.render('allrestaurants', { restaurants });
    } catch (error) {
        console.error('Error fetching restaurants', error);
        res.status(500).send('Internal server error');
    }
});
app.get('/order/:restaurantid', authorizerequest, async (req, res) => {
    try {
      const { restaurantid } = req.params;
      const restaurant = await restaurantowner.findById(restaurantid);
      if (!restaurant) {
        return res.status(404).send('Restaurant not found');
      }
      res.render('orderpage', { restaurant });
    } catch (error) {
      console.error('Error fetching restaurant for order', error);
      res.status(500).send('Internal server error');
    }
  });
  
  app.post('/order', authorizerequest, async (req, res) => {
    try {
      const { restaurantname, restaurantid } = req.body;
      const { userid } = req;
      const items = [];
    
      for (const key in req.body) {
        if (key.startsWith('quantity_')) {
          const itemid = key.replace('quantity_', '');
          const quantity = parseInt(req.body[key], 10);
          if (quantity > 0) {
            const menuItem = await restaurantowner.findOne(
              { _id: restaurantid, 'menu._id': itemid }, 
              { 'menu.$': 1 }
            );
            if (menuItem) {
              items.push({
                itemname: menuItem.menu[0].itemname,
                price: menuItem.menu[0].price,
                quantity,
                total: menuItem.menu[0].price * quantity
              });
            }
          }
        }
      }
    
      if (items.length === 0) {
        return res.status(400).send('No items selected');
      }
    
      const order = new orders({
        orderid: `ORD-${Date.now()}`,
        restaurantname,
        username: userid,
        items,
        totalprice: items.reduce((total, item) => total + item.total, 0).toFixed(2),
        status: 'Pending'
      });
    
      await order.save();
      res.redirect(`/order/confirmation/${order.orderid}`);
    } catch (error) {
      console.error('Error placing order', error);
      res.status(500).send('Internal server error');
    }
  });
app.get('/order/confirmation/:orderid', authorizerequest, async (req, res) => {
    try {
      const { orderid } = req.params;
      const order = await orders.findOne({ orderid });
      if (!order) {
        return res.status(404).send('Order not found');
      }
      res.render('orderconfirmation', { order });
    } catch (error) {
      console.error('Error fetching order confirmation', error);
      res.status(500).send('Internal server error');
    }
  });

app.post('/order/:orderid/place', async (req, res) => {
    try {
        const { orderid } = req.params;
        const order = await orders.findById(orderid);
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        res.render('orderconfirmation', { order });
    } catch (error) {
        console.error('Error placing the order', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


  app.post('/order/:orderid/delete',authorizerequest,async (req, res) => {
    try {
      const { orderid } = req.params;
      const deletedOrder = await orders.findOneAndDelete({ _id: orderid });
      if (!deletedOrder) {
        return res.status(404).json({ error: 'Order not found' });
      }
  
      res.redirect('/restaurants'); 
    } catch (error) {
      console.error('Error deleting order', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  
  
  app.get('/order/status/:orderid', authorizerequest, async (req, res) => {
    try {
      const { orderid } = req.params;
      const order = await orders.findOne({ orderid });
      if (!order) {
        return res.status(404).send('Order not found');
      }
      res.json({ status: order.status });
    } catch (error) {
      console.error('Error fetching order status', error);
      res.status(500).send('Internal server error');
    }
  });

app.get('/order/:orderid/status', async (req, res) => {
    try {
        const { orderid } = req.params;
        const order = await orders.findById(orderid);
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        res.json({ status: order.status });
    } catch (error) {
        console.error('Error fetching order status', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/owner/orders/:orderid/update', authorizerequest, async (req, res) => {
    try {
      const { orderid } = req.params;
      const { status } = req.body;  

      const validStatuses = ['Pending', 'Confirmed', 'Cancelled', 'Delivered'];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status value' });
      }
      const updatedOrder = await orders.findByIdAndUpdate(orderid, { status, updatedat: Date.now() }, { new: true });
      if (!updatedOrder) {
        return res.status(404).json({ error: 'Order not found' });
      }
  
    //   res.json({ message: 'Order status updated successfully', order: updatedOrder });
    res.redirect('/owner');
    } catch (error) {
      console.error('Error updating order status', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  


  app.post('/owner/orders/:orderid/delete', authorizerequest, async (req, res) => {
    try {
      const { orderid } = req.params;

      const deletedOrder = await orders.findByIdAndDelete(orderid);
      if (!deletedOrder) {
        return res.status(404).json({ error: 'Order not found' });
      }
  
      res.redirect('/owner');

    } catch (error) {
      console.error('Error deleting order', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  
app.post('/logout', (req,res)=>
{
    res.cookie('token');
    res.redirect('/');
})

const port = 3000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
