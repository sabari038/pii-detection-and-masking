import React, { useState } from 'react';
import axios from 'axios';
import './App.css'; // Ensure this file includes the CSS provided earlier

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [piiData, setPiiData] = useState({});
  const [editedPiiData, setEditedPiiData] = useState({});
  const [maskedFilePath, setMaskedFilePath] = useState('');
  const [filePath, setFilePath] = useState('');
  const [isFileUploaded, setIsFileUploaded] = useState(false);
  const [isPiiVerified, setIsPiiVerified] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [imageMaskingOption, setImageMaskingOption] = useState('none'); // New state for image masking

  const handleFileChange = async (event) => {
    const file = event.target.files[0];
    if (!file) {
      alert('Please select a file.');
      return;
    }

    setSelectedFile(file);
    setIsFileUploaded(false);
    setPiiData({});
    setEditedPiiData({});
    setMaskedFilePath('');
    setScanResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      // Step 1: Scan for malicious content
      const scanResponse = await axios.post('http://127.0.0.1:5000/scan_and_upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      setScanResult(scanResponse.data);

      if (scanResponse.data.malicious) {
        alert('Alert: Malicious content detected!');
        return; // Stop further processing if the file is malicious
      }

      // Step 2: If no malicious content, proceed to PII verification
      alert('File is safe. Proceeding to PII verification.');

      setPiiData(scanResponse.data.pii_list);
      setFilePath(scanResponse.data.file_path);
      setEditedPiiData({});
      setIsPiiVerified(true);
      setIsFileUploaded(true);
    } catch (error) {
      console.error('Error processing file:', error);
    }
  };

  const handleActionChange = (key, action) => {
    const value = piiData[key];
    let updatedValue = value;

    if (action === 'Mask') {
      updatedValue = '*'.repeat(value.length);
    } else if (action === 'Delete') {
      updatedValue = ' '.repeat(value.length);
    } else if (action === 'Redact') {
      updatedValue = '[Hidden]';
    }

    setEditedPiiData((prevData) => ({
      ...prevData,
      [key]: updatedValue,
    }));
  };

  const handleImageMaskingChange = (event) => {
    setImageMaskingOption(event.target.value);
  };

  const handleMask = async () => {
    if (Object.keys(editedPiiData).length === 0) {
      alert('Please select an action for detected PII before applying changes.');
      return;
    }

    try {
      const response = await axios.post('http://127.0.0.1:5000/mask', {
        file_path: filePath,
        edited_pii_data: editedPiiData,
        image_masking_options: { images: imageMaskingOption },
      });
      console.log('Mask response:', response.data);
      setMaskedFilePath(response.data.file_path);
      console.log(response.data.file_path)
    } catch (error) {
      console.error('Error masking PII:', error);
    }
  };

  const handleDownload = () => {
    window.location.href = `http://127.0.0.1:5000/download/${maskedFilePath}`;
  };

  return (
    <div className="App">
      <h1>PII Detector and Masker</h1>
      <input type="file" id="fileInput" onChange={handleFileChange} />
      <label htmlFor="fileInput">Upload Document</label>

      {isFileUploaded && isPiiVerified && Object.keys(piiData).length > 0 && (
        <div>
          <h2>Detected PII:</h2>
          <ul>
            {Object.entries(piiData).map(([key, value], index) => (
              <li key={index}>
                {key} - {value}
                <select onChange={(e) => handleActionChange(key, e.target.value)}>
                  <option value="">Select Action</option>
                  <option value="Redact">Redact</option>
                  <option value="Delete">Delete</option>
                  <option value="Mask">Mask</option>
                </select>
              </li>
            ))}
          </ul>
          <h2>Image/QR Code/Signature Masking:</h2>
          <select onChange={handleImageMaskingChange} value={imageMaskingOption}>
            <option value="none">None</option>
            <option value="blur">Blur</option>
            <option value="remove">Remove</option>
          </select>
          <button onClick={handleMask}>Apply Changes</button>
        </div>
      )}

      {maskedFilePath && (
        <div>
          <button onClick={handleDownload}>Download Masked File</button>
        </div>
      )}
    </div>
  );
}

export default App;