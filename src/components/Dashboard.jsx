/* eslint-disable react/prop-types */
import axios from 'axios';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

const Dashboard = ({ token, username, onLogout }) => {
  const [user, setUser] = useState(null);
  const [imageFile, setImageFile] = useState(null);
  const [imageUrl, setImageUrl] = useState('');
  const [uploadStatus, setUploadStatus] = useState('');

  useEffect(() => {
    const fetchUserProfile = async () => {
      try {
        const response = await axios.get(`http://localhost:5000/profile/${username}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        setUser(response.data);
        if (response.data.id) {
          // Qui la richiesta per ottenere l'immagine del profilo secondo l'id
          const imageResponse = await axios.get(`http://localhost:5000/image/${response.data.id}`, {
            responseType: 'blob',
            headers: { 'Authorization': `Bearer ${token}` }
          });
          const imageUrl = URL.createObjectURL(imageResponse.data);
          setImageUrl(imageUrl);
        }
      } catch (error) {
        console.error('Error fetching user profile:', error);
      }
    };
  
    fetchUserProfile();
  }, [username, token]);
  

  const handleImageChange = (event) => {
    setImageFile(event.target.files[0]);
  };

  const handleUpload = async () => {
    if (!imageFile) {
      setUploadStatus('Please select an image to upload.');
      return;
    }

    const formData = new FormData();
    formData.append('profileImage', imageFile);

    try {
      const response = await axios.post(`http://localhost:5000/upload/${user.id}`, formData, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        }
      });

      if (response.status === 200) {
        setUploadStatus('Image uploaded successfully!');
        setImageUrl(URL.createObjectURL(imageFile)); // aggiorna l'immagine
      } else {
        setUploadStatus('Failed to upload image.');
      }
    } catch (error) {
      console.error('Error uploading image:', error);
      setUploadStatus('Error uploading image.');
    }
  };

  if (!user) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <div className='main'>
      {imageUrl && <img src={imageUrl} alt="Profile" className="profile-image" />}
      <h1>Welcome, {user.fullname}!</h1>
      </div>
      <div className="upload-container">
        <input type="file" onChange={handleImageChange} />
        <button className='upload' onClick={handleUpload}>Change Profile Image</button>
        {uploadStatus && <p className="upload-status">{uploadStatus}</p>}
      </div>
     
      <p>Username: {user.username}</p>
      <p>Email: {user.email}</p>      
     
      <Link to={`/edit-profile/${user.username}`}>Edit Profile</Link>
      <button onClick={onLogout}>Logout</button>
    </div>
  );
};

export default Dashboard;
