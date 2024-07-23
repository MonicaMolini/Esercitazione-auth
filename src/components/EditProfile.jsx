import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';

// eslint-disable-next-line react/prop-types
const EditProfile = ({ token }) => {
  const { username } = useParams();
  const navigate = useNavigate(); 
  const [userData, setUserData] = useState({
    username: '',
    password: '',
    email: '',
    fullname: '',
  });

  useEffect(() => {
    const fetchUserProfile = async () => {
      try {
        const response = await axios.get(`http://localhost:5000/profile/${username}`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        setUserData(response.data);
      } catch (error) {
        console.error('Error fetching user profile:', error);
      }
    };

    fetchUserProfile();
  }, [username, token]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setUserData((prevData) => ({
      ...prevData,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      await axios.put(`http://localhost:5000/update/${userData.id}`, {
        username: userData.username,
        password: userData.password,
        email: userData.email,
        fullname: userData.fullname,
      }, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      alert('User updated successfully');
      navigate('/dashboard');
    } catch (error) {
      console.error('Error updating user:', error);
      alert('Failed to update user');
    }
  };

  const handleCancel = () => {
    navigate('/dashboard');  
  };

  return (
    <div>
      <h2>Edit Profile</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <label>Username:</label>
          <input type="text" name="username" value={userData.username} onChange={handleChange} required />
        </div>
        <div>
          <label>Password:</label>
          <input type="password" name="password" value={userData.password || ''} onChange={handleChange} required />
        </div>
        <div>
          <label>Email:</label>
          <input type="email" name="email" value={userData.email} onChange={handleChange} required />
        </div>
        <div>
          <label>Fullname:</label>
          <input type="text" name="fullname" value={userData.fullname} onChange={handleChange} required />
        </div>
        <button type="submit">Update Profile</button>
        <button type="button" onClick={handleCancel}>Cancel</button>
      </form>
    </div>
  );
};

export default EditProfile;
