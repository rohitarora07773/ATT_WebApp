import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';
import './App.css';

// Import UI components
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Label } from './components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { Badge } from './components/ui/badge';
import { Alert, AlertDescription } from './components/ui/alert';
import { Separator } from './components/ui/separator';
import { Textarea } from './components/ui/textarea';
import { Toaster } from './components/ui/toaster';
import { useToast } from './hooks/use-toast';
import { 
  User, 
  CreditCard, 
  Upload, 
  FileText, 
  LogOut, 
  Lock,
  Smartphone,
  Download,
  RefreshCw,
  CheckCircle,
  Clock,
  XCircle,
  AlertCircle
} from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = React.createContext();

function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      fetchCurrentUser(token);
    } else {
      setLoading(false);
    }
  }, []);

  const fetchCurrentUser = async (token) => {
    try {
      const response = await axios.get(`${API}/auth/me`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUser(response.data);
    } catch (error) {
      localStorage.removeItem('token');
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    try {
      const response = await axios.post(`${API}/auth/login`, { email, password });
      localStorage.setItem('token', response.data.token);
      setUser(response.data.user);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.response?.data?.detail || 'Login failed' };
    }
  };

  const signup = async (userData) => {
    try {
      const response = await axios.post(`${API}/auth/signup`, userData);
      localStorage.setItem('token', response.data.token);
      setUser(response.data.user);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.response?.data?.detail || 'Signup failed' };
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    setUser(null);
  };

  const refreshUser = async () => {
    const token = localStorage.getItem('token');
    if (token) {
      await fetchCurrentUser(token);
    }
  };

  return (
    <AuthContext.Provider value={{ user, login, signup, logout, loading, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

const useAuth = () => {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// API Helper
const apiCall = async (endpoint, options = {}) => {
  const token = localStorage.getItem('token');
  const config = {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options.headers,
    },
  };
  
  try {
    const response = await axios(`${API}${endpoint}`, config);
    return { success: true, data: response.data };
  } catch (error) {
    return { 
      success: false, 
      error: error.response?.data?.detail || error.message 
    };
  }
};

// Login/Signup Page
function AuthPage() {
  const { login, signup } = useAuth();
  const { toast } = useToast();
  const [isLogin, setIsLogin] = useState(true);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    first_name: '',
    last_name: '',
    email: '',
    confirm_email: '',
    password: ''
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      let result;
      if (isLogin) {
        result = await login(formData.email, formData.password);
      } else {
        result = await signup(formData);
      }

      if (result.success) {
        toast({
          title: "Success!",
          description: isLogin ? "Logged in successfully" : "Account created successfully",
        });
      } else {
        toast({
          title: "Error",
          description: result.error,
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Something went wrong. Please try again.",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-xl">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 w-20 h-20 bg-blue-600 rounded-full flex items-center justify-center">
            <Smartphone className="w-10 h-10 text-white" />
          </div>
          <CardTitle className="text-2xl font-bold text-slate-800">
            Device Unlock Hub
          </CardTitle>
          <CardDescription>
            {isLogin ? 'Sign in to your account' : 'Create your account and get 100 free credits'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {!isLogin && (
              <>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="first_name">First Name</Label>
                    <Input
                      id="first_name"
                      name="first_name"
                      type="text"
                      value={formData.first_name}
                      onChange={handleInputChange}
                      required
                      className="transition-colors focus:ring-blue-500"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="last_name">Last Name</Label>
                    <Input
                      id="last_name"
                      name="last_name"
                      type="text"
                      value={formData.last_name}
                      onChange={handleInputChange}
                      required
                      className="transition-colors focus:ring-blue-500"
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="confirm_email">Confirm Email</Label>
                  <Input
                    id="confirm_email"
                    name="confirm_email"
                    type="email"
                    value={formData.confirm_email}
                    onChange={handleInputChange}
                    required
                    className="transition-colors focus:ring-blue-500"
                  />
                </div>
              </>
            )}
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                name="email"
                type="email"
                value={formData.email}
                onChange={handleInputChange}
                required
                className="transition-colors focus:ring-blue-500"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                name="password"
                type="password"
                value={formData.password}
                onChange={handleInputChange}
                required
                className="transition-colors focus:ring-blue-500"
              />
              {!isLogin && (
                <p className="text-xs text-slate-600">
                  Password must contain: 8+ characters, uppercase, lowercase, number, and special character
                </p>
              )}
            </div>
            <Button 
              type="submit" 
              className="w-full bg-blue-600 hover:bg-blue-700 transition-colors"
              disabled={loading}
            >
              {loading ? 'Processing...' : (isLogin ? 'Sign In' : 'Create Account')}
            </Button>
          </form>
          <div className="mt-4 text-center">
            <Button
              variant="link"
              onClick={() => setIsLogin(!isLogin)}
              className="text-blue-600 hover:text-blue-700"
            >
              {isLogin ? "Don't have an account? Sign up" : "Already have an account? Sign in"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// Main Dashboard Layout
function DashboardLayout({ children }) {
  const { user, logout, refreshUser } = useAuth();
  const [activeMenu, setActiveMenu] = useState('dashboard');

  useEffect(() => {
    refreshUser();
  }, []);

  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: FileText },
    { id: 'device-unlock', label: 'Device Unlock', icon: Smartphone, submenu: [
      { id: 'att', label: 'ATT', parent: 'device-unlock' }
    ]},
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'change-password', label: 'Change Password', icon: Lock },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="flex justify-between items-center px-6 py-4">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <Smartphone className="w-5 h-5 text-white" />
            </div>
            <h1 className="text-xl font-bold text-slate-800">Device Unlock Hub</h1>
          </div>
          <div className="flex items-center space-x-4">
            <Badge variant="outline" className="flex items-center space-x-1 px-3 py-1">
              <CreditCard className="w-4 h-4" />
              <span>{user?.credits || 0} Credits</span>
            </Badge>
            <Button
              variant="outline"
              size="sm"
              onClick={logout}
              className="flex items-center space-x-2"
            >
              <LogOut className="w-4 h-4" />
              <span>Logout</span>
            </Button>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <nav className="w-64 bg-white shadow-sm min-h-screen border-r border-gray-200">
          <div className="p-4">
            <ul className="space-y-2">
              {menuItems.map((item) => (
                <li key={item.id}>
                  <button
                    onClick={() => setActiveMenu(item.id)}
                    className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-left transition-colors ${
                      activeMenu === item.id
                        ? 'bg-blue-100 text-blue-700'
                        : 'text-gray-700 hover:bg-gray-100'
                    }`}
                  >
                    <item.icon className="w-5 h-5" />
                    <span>{item.label}</span>
                  </button>
                  {item.submenu && (activeMenu === item.id || item.submenu.some(sub => sub.id === activeMenu)) && (
                    <ul className="ml-8 mt-2 space-y-1">
                      {item.submenu.map((subItem) => (
                        <li key={subItem.id}>
                          <button
                            onClick={() => setActiveMenu(subItem.id)}
                            className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                              activeMenu === subItem.id
                                ? 'bg-blue-50 text-blue-600'
                                : 'text-gray-600 hover:bg-gray-50'
                            }`}
                          >
                            {subItem.label}
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ul>
          </div>
        </nav>

        {/* Main Content */}
        <main className="flex-1 p-6">
          {React.cloneElement(children, { activeMenu, setActiveMenu })}
        </main>
      </div>
    </div>
  );
}

// Dashboard Content Components
function Dashboard() {
  const { user } = useAuth();

  return (
    <div className="space-y-6">
      <div>  
        <h2 className="text-2xl font-bold text-slate-800">Welcome back, {user?.first_name}!</h2>
        <p className="text-gray-600">Manage your device unlock requests</p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Available Credits</CardTitle>
            <CreditCard className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600">{user?.credits || 0}</div>
            <p className="text-xs text-muted-foreground">
              Each unlock request uses 1 credit
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Account Status</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">Active</div>
            <p className="text-xs text-muted-foreground">
              Member since {new Date(user?.created_at).toLocaleDateString()}
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Quick Actions</CardTitle>
            <Smartphone className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <Button className="w-full bg-blue-600 hover:bg-blue-700">
              Start ATT Unlock
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function ATTPage() {
  const { toast } = useToast();
  const { refreshUser } = useAuth();
  const [activeTab, setActiveTab] = useState('manual');
  const [imei, setImei] = useState('');
  const [file, setFile] = useState(null);
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    fetchRequests();
  }, []);

  const fetchRequests = async () => {
    setRefreshing(true);
    const result = await apiCall('/att/requests');
    if (result.success) {
      setRequests(result.data);
    }
    setRefreshing(false);
  };

  const handleManualSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    const result = await apiCall('/att/submit-imei', {
      method: 'POST',
      data: { imei }
    });

    if (result.success) {
      toast({
        title: "Success!",
        description: "IMEI submitted successfully",
      });
      setImei('');
      await fetchRequests();
      await refreshUser();
    } else {
      toast({
        title: "Error",
        description: result.error,
        variant: "destructive",
      });
    }
    setLoading(false);
  };

  const handleFileUpload = async (e) => {
    e.preventDefault();
    if (!file) return;

    setLoading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const token = localStorage.getItem('token');
      const response = await axios.post(`${API}/att/upload-file`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          Authorization: `Bearer ${token}`,
        },
      });

      toast({
        title: "Success!",
        description: response.data.message,
      });
      setFile(null);
      await fetchRequests();
      await refreshUser();
    } catch (error) {
      toast({
        title: "Error",
        description: error.response?.data?.detail || 'Upload failed',
        variant: "destructive",
      });
    }
    setLoading(false);
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'processing':
        return <Clock className="w-4 h-4 text-yellow-500" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-red-500" />;
      default:
        return <AlertCircle className="w-4 h-4 text-blue-500" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'processing':
        return 'bg-yellow-100 text-yellow-800';
      case 'failed':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-blue-100 text-blue-800';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-slate-800">ATT Device Unlock</h2>
          <p className="text-gray-600">Submit IMEI numbers for unlock processing</p>
        </div>
        <Button
          onClick={fetchRequests}
          disabled={refreshing}
          variant="outline"
          size="sm"
          className="flex items-center space-x-2"
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Submit IMEI for Processing</CardTitle>
          <CardDescription>
            Choose to enter IMEI manually or upload a file
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="manual">Manual Entry</TabsTrigger>
              <TabsTrigger value="upload">File Upload</TabsTrigger>
            </TabsList>
            
            <TabsContent value="manual" className="space-y-4">
              <form onSubmit={handleManualSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="imei">IMEI Number</Label>
                  <Input
                    id="imei"
                    type="text"
                    placeholder="Enter 15-digit IMEI number"
                    value={imei}
                    onChange={(e) => setImei(e.target.value)}
                    maxLength={15}
                    pattern="[0-9]{15}"
                    required
                    className="font-mono"
                  />
                  <p className="text-sm text-gray-500">
                    IMEI must be exactly 15 digits
                  </p>
                </div>
                <Button 
                  type="submit" 
                  disabled={loading || imei.length !== 15}
                  className="bg-blue-600 hover:bg-blue-700"
                >
                  {loading ? 'Submitting...' : 'Submit IMEI'}
                </Button>
              </form>
            </TabsContent>
            
            <TabsContent value="upload" className="space-y-4">
              <form onSubmit={handleFileUpload} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="file">Upload File</Label>
                  <Input
                    id="file"
                    type="file"
                    accept=".xlsx,.xls,.csv"
                    onChange={(e) => setFile(e.target.files[0])}
                    required
                  />
                  <div className="text-sm text-gray-500 space-y-1">
                    <p>• Accepted formats: Excel (.xlsx, .xls) or CSV (.csv)</p>
                    <p>• File must contain a column named "IMEI"</p>
                    <p>• Each IMEI must be exactly 15 digits</p>
                  </div>
                </div>
                <Button 
                  type="submit" 
                  disabled={loading || !file}
                  className="bg-blue-600 hover:bg-blue-700"
                >
                  <Upload className="w-4 h-4 mr-2" />
                  {loading ? 'Uploading...' : 'Upload File'}
                </Button>
              </form>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Requests Table */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Requests</CardTitle>
          <CardDescription>
            Track the status of your IMEI unlock requests
          </CardDescription>
        </CardHeader>
        <CardContent>
          {requests.length > 0 ? (
            <div className="space-y-4">
              {requests.map((request) => (
                <div key={request.id} className="border rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      {getStatusIcon(request.status)}
                      <div>
                        <p className="font-mono font-medium">{request.imei}</p>
                        <p className="text-sm text-gray-500">
                          {new Date(request.created_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-3">
                      <Badge className={getStatusColor(request.status)}>
                        {request.status}
                      </Badge>
                      {request.request_number && (
                        <Badge variant="outline">
                          #{request.request_number}
                        </Badge>
                      )}
                    </div>
                  </div>
                  {request.response && (
                    <div className="mt-3 p-3 bg-gray-50 rounded">
                      <p className="text-sm text-gray-700">{request.response}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              <Smartphone className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No requests yet. Submit your first IMEI to get started!</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Profile() {
  const { user } = useAuth();

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-slate-800">Profile</h2>
        <p className="text-gray-600">Your account information</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Personal Information</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>First Name</Label>
              <p className="mt-1 font-medium">{user?.first_name}</p>
            </div>
            <div>
              <Label>Last Name</Label>
              <p className="mt-1 font-medium">{user?.last_name}</p>
            </div>
          </div>
          <div>
            <Label>Email Address</Label>
            <p className="mt-1 font-medium">{user?.email}</p>
          </div>
          <div>
            <Label>Member Since</Label>
            <p className="mt-1 font-medium">
              {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
            </p>
          </div>
          <div>
            <Label>Available Credits</Label>
            <p className="mt-1 font-medium text-blue-600">{user?.credits || 0}</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function ChangePassword() {
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    current_password: '',
    new_password: ''
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    const result = await apiCall('/auth/change-password', {
      method: 'POST',
      data: formData
    });

    if (result.success) {
      toast({
        title: "Success!",
        description: "Password changed successfully",
      });
      setFormData({ current_password: '', new_password: '' });
    } else {
      toast({
        title: "Error",
        description: result.error,
        variant: "destructive",
      });
    }
    setLoading(false);
  };

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-slate-800">Change Password</h2>
        <p className="text-gray-600">Update your account password</p>
      </div>

      <Card className="max-w-md">
        <CardHeader>
          <CardTitle>Change Password</CardTitle>
          <CardDescription>
            Enter your current password and choose a new one
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="current_password">Current Password</Label>
              <Input
                id="current_password"
                name="current_password"
                type="password"
                value={formData.current_password}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="new_password">New Password</Label>
              <Input
                id="new_password"
                name="new_password"
                type="password"
                value={formData.new_password}
                onChange={handleInputChange}
                required
              />
              <p className="text-xs text-gray-500">
                Password must contain: 8+ characters, uppercase, lowercase, number, and special character
              </p>
            </div>
            <Button 
              type="submit" 
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700"
            >
              {loading ? 'Changing...' : 'Change Password'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

// Main Content Router
function MainContent({ activeMenu }) {
  switch (activeMenu) {
    case 'dashboard':
      return <Dashboard />;
    case 'att':
      return <ATTPage />;
    case 'profile':
      return <Profile />;
    case 'change-password':
      return <ChangePassword />;
    default:
      return <Dashboard />;
  }
}

// Main App Component
function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="App">
      {user ? (
        <DashboardLayout>
          <MainContent />
        </DashboardLayout>
      ) : (
        <AuthPage />
      )}
      <Toaster />
    </div>
  );
}

// Root App with AuthProvider
export default function AppWithAuth() {
  return (
    <AuthProvider>
      <App />
    </AuthProvider>
  );
}