import { useEffect } from 'react'
import { HashRouter, Routes, Route, useLocation } from 'react-router-dom';
import Layout from './components/Layout';
import HomePage from './pages/HomePage';
import D2Page  from './pages/d2/D2Page';
import D3Page  from './pages/d3/D3Page';
import D5Page from './pages/d5/D5Page';
import D6Page from './pages/d6/D6Page';
import './styles/globals.css'

function ScrollToTop() {
  const { pathname } = useLocation()
  useEffect(() => { window.scrollTo(0, 0) }, [pathname])
  return null
}

export default function App() {
  return (
    <HashRouter>
      <ScrollToTop />
      <Layout>
        <Routes>
          <Route path="/"   element={<HomePage />} />
          <Route path="/d2" element={<D2Page />} />
          <Route path="/d3" element={<D3Page />} />
          <Route path="/d5" element={<D5Page />} />
          <Route path="/d6" element={<D6Page />} />
        </Routes>
      </Layout>
    </HashRouter>
  )
}