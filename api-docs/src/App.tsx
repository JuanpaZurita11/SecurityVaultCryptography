import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import HomePage from './pages/HomePage';
import D2Page  from './pages/d2/D2Page';
import './styles/globals.css'

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/"   element={<HomePage />} />
          <Route path="/d2" element={<D2Page />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}
